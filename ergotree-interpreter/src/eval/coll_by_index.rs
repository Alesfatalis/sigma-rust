use ergotree_ir::mir::coll_by_index::ByIndex;
use ergotree_ir::mir::constant::TryExtractInto;
use ergotree_ir::mir::value::CollKind;
use ergotree_ir::mir::value::Value;

use crate::eval::env::Env;
use crate::eval::Context;
use crate::eval::EvalError;
use crate::eval::Evaluable;

impl Evaluable for ByIndex {
    fn eval<'ctx>(
        &self,
        env: &mut Env<'ctx>,
        ctx: &Context<'ctx>,
    ) -> Result<Value<'ctx>, EvalError> {
        let input_v = self.input.eval(env, ctx)?;
        let index_v = self.index.eval(env, ctx)?;
        let normalized_input_vals: &CollKind<Value<'ctx>> = match &input_v {
            Value::Coll(coll) => Ok(coll),
            _ => Err(EvalError::UnexpectedValue(format!(
                "ByIndex: expected input to be Value::Coll, got: {0:?}",
                input_v
            ))),
        }?;
        match self.default.clone() {
            Some(default) => {
                let default_v = default.eval(env, ctx)?;
                Ok(normalized_input_vals
                    .get_val(index_v.try_extract_into::<i32>()? as usize)
                    .unwrap_or(default_v))
            }
            None => normalized_input_vals
                .get_val(index_v.clone().try_extract_into::<i32>()? as usize)
                .ok_or_else(|| {
                    EvalError::Misc(format!(
                        "ByIndex: index {0:?} out of bounds for collection size {1:?}",
                        index_v,
                        normalized_input_vals.len()
                    ))
                }),
        }
    }
}

#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use ergotree_ir::chain::ergo_box::ErgoBox;
    use ergotree_ir::mir::expr::Expr;
    use ergotree_ir::mir::global_vars::GlobalVars;
    use ergotree_ir::reference::Ref;
    use sigma_test_util::force_any_val;

    use super::*;
    use crate::eval::tests::eval_out;
    use crate::eval::tests::eval_out_wo_ctx;
    use ergotree_ir::chain::context::Context;

    #[test]
    fn eval() {
        let expr: Expr = ByIndex::new(GlobalVars::Outputs.into(), Expr::Const(0i32.into()), None)
            .unwrap()
            .into();
        let ctx = force_any_val::<Context>();
        assert_eq!(
            eval_out::<Ref<'_, ErgoBox>>(&expr, &ctx).box_id(),
            ctx.outputs.first().unwrap().box_id()
        );
    }

    #[test]
    fn eval_with_default() {
        let expr: Expr = ByIndex::new(
            Expr::Const(vec![1i64, 2i64].into()),
            Expr::Const(3i32.into()),
            Some(Box::new(Expr::Const(5i64.into()))),
        )
        .unwrap()
        .into();
        assert_eq!(eval_out_wo_ctx::<i64>(&expr), 5);
    }
}
