//! Operators in ErgoTree

use eval::costs::Costs;

use crate::eval;
use crate::eval::Env;
use crate::eval::EvalContext;
use crate::eval::EvalError;
use crate::eval::Evaluable;

use super::expr::Expr;
use super::value::Value;
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
/// Operations for numerical types
pub enum NumOp {
    /// Addition
    Add,
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum LogicOp {
    Eq,
    Neq,
    GE,
    GT,
    LE,
    LT,
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
/// Binary operations
pub enum BinOpKind {
    /// Binary operations for numerical types
    Num(NumOp),
    Logic(LogicOp),
}

// TODO: extract into ops::bin_op
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct BinOp {
    pub kind: BinOpKind,
    pub left: Expr,
    pub right: Expr,
}

impl Evaluable for BinOp {
    fn eval(&self, env: &Env, ctx: &mut EvalContext) -> Result<Value, EvalError> {
        let lv = self.left.eval(env, ctx)?;
        let rv = self.right.eval(env, ctx)?;
        ctx.cost_accum.add(Costs::DEFAULT.eq_const_size)?;
        match self.kind {
            BinOpKind::Num(_) => todo!(),
            BinOpKind::Logic(op) => match op {
                LogicOp::Eq => Ok(Value::Boolean(lv == rv)),
                _ => todo!(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use crate::ast::constant::Constant;
    use crate::eval::context::Context;
    use crate::eval::tests::eval_out;
    use crate::test_util::force_any_val;

    use super::*;

    fn check_eq(left: Constant, right: Constant) -> bool {
        let eq_op: Expr = Box::new(BinOp {
            kind: BinOpKind::Logic(LogicOp::Eq),
            left: Box::new(left).into(),
            right: Box::new(right).into(),
        })
        .into();
        let ctx = Rc::new(force_any_val::<Context>());
        eval_out::<bool>(&eq_op, ctx)
    }

    #[test]
    fn num_eq() {
        assert!(check_eq(1i64.into(), 1i64.into()));
    }

    #[test]
    fn num_neq() {
        assert!(!check_eq(2i64.into(), 1i64.into()));
    }

    #[test]
    fn option_eq() {
        assert!(check_eq(Some(1i64).into(), Some(1i64).into()));
        let none: Option<i64> = None;
        assert!(check_eq(none.into(), none.into()));
        // Option<Vec<i8>>
        assert!(check_eq(
            Some(vec![1i8, 2i8]).into(),
            Some(vec![1i8, 2i8]).into()
        ));
        // Vec<Option<i64>>
        assert!(check_eq(
            vec![Some(1i64), Some(1i64)].into(),
            vec![Some(1i64), Some(1i64)].into()
        ));
    }

    #[test]
    fn option_neq() {
        assert!(!check_eq(Some(2i64).into(), Some(1i64).into()));
        let none: Option<i64> = None;
        assert!(!check_eq(none.into(), Some(1i64).into()));
        // Option<Vec<i8>>
        assert!(!check_eq(
            Some(vec![1i8, 2i8]).into(),
            Some(vec![2i8, 2i8]).into()
        ));
        // Vec<Option<i64>>
        assert!(!check_eq(
            vec![Some(1i64), Some(1i64)].into(),
            vec![Some(2i64), Some(1i64)].into()
        ));
    }
}
