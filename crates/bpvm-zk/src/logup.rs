//! The reciprocal (logUp) argument in Bulletproofs R1CS, and lookups built on it.
//!
//! A [`LogUp`] instance collects terms $\pm 1/(c + \langle\alpha, x\rangle)$ for tuples $x$
//! and proves that they sum to zero, with challenges $\alpha, c$ drawn after all tuples
//! (phase-1 variables) are committed:
//!
//! $$\sum_{x \in A} \frac{1}{c+\langle\alpha,x\rangle} - \sum_{y \in B} \frac{1}{c+\langle\alpha,y\rangle}
//!   + \sum_j \frac{\mu_j}{c+\langle\alpha,t_j\rangle} = 0.$$
//!
//! Except with negligible probability this means $A \uplus \{t_j^{\mu_j}\} = B$ as multisets
//! (counts must stay below the field characteristic, trivially true here). One identity
//! serves three purposes:
//!
//! - **lookup**: queries on one side, public table rows weighted by committed multiplicities;
//! - **bus**: tuples sent by the CPU chip vs tuples received by opcode chips;
//! - **memory**: reads and final values vs writes and initial values.
//!
//! Cost: one multiplier per witness tuple ($r \cdot (c + \langle\alpha,x\rangle) = 1$);
//! public tuples are free (their coefficient $1/(c+\langle\alpha,t\rangle)$ is a constant).
//! Generalises the digit check in `zero-art-rs/bulletproofs/tests/reciprocal.rs`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use bulletproofs::r1cs::{
    ConstraintSystem, LinearCombination, R1CSError, RandomizableConstraintSystem,
    RandomizedConstraintSystem, Variable,
};
use curve25519_dalek::scalar::Scalar;

/// Signed sum of reciprocals over committed and public tuples (see module docs).
pub struct LogUp {
    width: usize,
    /// `(negated, tuple)` — tuples over phase-1 variables, coefficient $\pm 1$.
    witness: Vec<(bool, Vec<LinearCombination>)>,
    /// `(coefficient, row)` — public tuples with a linear-combination coefficient.
    public: Vec<(LinearCombination, Vec<Scalar>)>,
}

impl LogUp {
    pub fn new(width: usize) -> Self {
        assert!(width > 0);
        LogUp { width, witness: Vec::new(), public: Vec::new() }
    }

    /// Add $+1/(c+\langle\alpha,x\rangle)$.
    pub fn add(&mut self, x: Vec<LinearCombination>) {
        assert_eq!(x.len(), self.width, "tuple width mismatch");
        self.witness.push((false, x));
    }

    /// Add $-1/(c+\langle\alpha,x\rangle)$.
    pub fn sub(&mut self, x: Vec<LinearCombination>) {
        assert_eq!(x.len(), self.width, "tuple width mismatch");
        self.witness.push((true, x));
    }

    /// Add $\mu/(c+\langle\alpha,t\rangle)$ for a public row $t$.
    pub fn add_public(&mut self, coeff: LinearCombination, t: Vec<Scalar>) {
        assert_eq!(t.len(), self.width, "row width mismatch");
        self.public.push((coeff, t));
    }

    /// Number of multipliers this argument adds in phase 2.
    pub fn phase2_multipliers(&self) -> usize {
        self.witness.len()
    }

    pub fn is_empty(&self) -> bool {
        self.witness.is_empty() && self.public.is_empty()
    }

    pub fn finalize<CS: RandomizableConstraintSystem>(self, cs: &mut CS) -> Result<(), R1CSError> {
        if self.is_empty() {
            return Ok(());
        }
        let LogUp { width, witness, public } = self;
        cs.specify_randomized_constraints(move |cs| {
            let alpha = if width > 1 { cs.challenge_scalar(b"logup alpha") } else { Scalar::ONE };
            let c = cs.challenge_scalar(b"logup c");
            let alpha_pows: Vec<Scalar> =
                std::iter::successors(Some(Scalar::ONE), |p| Some(p * alpha)).take(width).collect();

            let mut sum = LinearCombination::default();
            for (negated, x) in witness {
                let compressed = x
                    .into_iter()
                    .zip(&alpha_pows)
                    .fold(LinearCombination::from(c), |acc, (lc, a)| acc + lc * *a);
                let assignment = cs.eval(&compressed).map(|v| (v.invert(), v));
                let (r, d, o) = cs.allocate_multiplier(assignment)?;
                cs.constrain(d - compressed);
                cs.constrain(o - Scalar::ONE);
                sum = if negated { sum - r } else { sum + r };
            }

            let mut denoms: Vec<Scalar> = public
                .iter()
                .map(|(_, t)| t.iter().zip(&alpha_pows).fold(c, |acc, (t, a)| acc + t * a))
                .collect();
            Scalar::batch_invert(&mut denoms);
            for ((coeff, _), w) in public.into_iter().zip(denoms) {
                sum = sum + coeff * w;
            }

            cs.constrain(sum);
            Ok(())
        })
    }
}

/// A public table of fixed-width rows.
#[derive(Clone, Debug)]
pub struct Table {
    width: usize,
    rows: Vec<Vec<Scalar>>,
}

impl Table {
    pub fn new(width: usize, rows: Vec<Vec<Scalar>>) -> Self {
        assert!(width > 0);
        assert!(rows.iter().all(|r| r.len() == width), "row width mismatch");
        Table { width, rows }
    }

    /// Single column $\{0, \dots, 2^{bits}-1\}$.
    pub fn range(bits: u32) -> Self {
        Table::new(1, (0..1u64 << bits).map(|i| vec![Scalar::from(i)]).collect())
    }

    /// Rows $(a, b, f(a,b))$ for all $a, b < 2^{bits}$.
    pub fn binary_op(bits: u32, f: impl Fn(u64, u64) -> u64) -> Self {
        let n = 1u64 << bits;
        let rows = (0..n)
            .flat_map(|a| (0..n).map(move |b| (a, b)))
            .map(|(a, b)| vec![Scalar::from(a), Scalar::from(b), Scalar::from(f(a, b))])
            .collect();
        Table::new(3, rows)
    }

    pub fn width(&self) -> usize {
        self.width
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
}

static UNCHECKED: AtomicBool = AtomicBool::new(false);

/// Testing aid: make the prover skip lookup queries that are not table rows instead of
/// failing, i.e. behave like a cheating prover. The resulting proof must not verify.
#[doc(hidden)]
pub fn set_unchecked_prover(on: bool) {
    UNCHECKED.store(on, Ordering::Relaxed);
}

fn row_key(row: &[Scalar]) -> Vec<u8> {
    row.iter().flat_map(|s| s.to_bytes()).collect()
}

/// Collects queries into one public table; [`Lookup::finalize`] commits multiplicities and
/// emits a single [`LogUp`], so all queries share the table-side cost ($|T|/2$ multipliers
/// for the multiplicities, plus one multiplier per query).
pub struct Lookup {
    table: Arc<Table>,
    queries: Vec<Vec<LinearCombination>>,
}

impl Lookup {
    pub fn new(table: Arc<Table>) -> Self {
        Lookup { table, queries: Vec::new() }
    }

    /// Assert that the tuple `q` (phase-1 variables only) is a row of the table.
    pub fn query(&mut self, q: Vec<LinearCombination>) {
        assert_eq!(q.len(), self.table.width, "query width mismatch");
        self.queries.push(q);
    }

    pub fn num_queries(&self) -> usize {
        self.queries.len()
    }

    /// Phase-2 multipliers: one per query (zero if unused).
    pub fn phase2_multipliers(&self) -> usize {
        self.queries.len()
    }

    /// Commit multiplicities (phase 1) and add the randomized reciprocal constraint
    /// (phase 2). An unused lookup adds nothing.
    pub fn finalize<CS: RandomizableConstraintSystem>(self, cs: &mut CS) -> Result<(), R1CSError> {
        let Lookup { table, queries } = self;
        if queries.is_empty() {
            return Ok(());
        }

        // Prover side: multiplicities from evaluated queries. The verifier gets `None`.
        let mult: Option<Vec<u64>> = match cs.eval(&queries[0][0]) {
            None => None,
            Some(_) => {
                let index: HashMap<Vec<u8>, usize> =
                    table.rows.iter().enumerate().map(|(i, r)| (row_key(r), i)).collect();
                let mut m = vec![0u64; table.len()];
                for q in &queries {
                    let vals: Vec<Scalar> = q.iter().map(|lc| cs.eval(lc).unwrap()).collect();
                    match index.get(&row_key(&vals)) {
                        Some(i) => m[*i] += 1,
                        None if UNCHECKED.load(Ordering::Relaxed) => {}
                        None => {
                            return Err(R1CSError::GadgetError {
                                description: "lookup query is not a table row".into(),
                            })
                        }
                    }
                }
                Some(m)
            }
        };

        let m_vars = (0..table.len())
            .map(|i| cs.allocate(mult.as_ref().map(|m| Scalar::from(m[i]))))
            .collect::<Result<Vec<Variable>, _>>()?;

        let mut arg = LogUp::new(table.width);
        for q in queries {
            arg.add(q);
        }
        for (m, row) in m_vars.into_iter().zip(table.rows.iter()) {
            arg.add_public(-LinearCombination::from(m), row.clone());
        }
        arg.finalize(cs)
    }
}
