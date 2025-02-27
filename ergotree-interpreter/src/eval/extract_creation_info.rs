use ergotree_ir::mir::extract_creation_info::ExtractCreationInfo;
use ergotree_ir::mir::value::Value;

use crate::eval::env::Env;
use crate::eval::Context;
use crate::eval::EvalError;
use crate::eval::Evaluable;

impl Evaluable for ExtractCreationInfo {
    fn eval<'ctx>(
        &self,
        env: &mut Env<'ctx>,
        ctx: &Context<'ctx>,
    ) -> Result<Value<'ctx>, EvalError> {
        let input_v = self.input.eval(env, ctx)?;
        match input_v {
            Value::CBox(b) => Ok(b.creation_info().into()),
            _ => Err(EvalError::UnexpectedValue(format!(
                "Expected ExtractCreationInfo input to be Value::CBox, got {0:?}",
                input_v
            ))),
        }
    }
}

#[allow(clippy::unwrap_used)]
#[cfg(test)]
#[cfg(feature = "arbitrary")]
mod tests {
    use crate::eval::tests::eval_out;
    use crate::eval::Context;

    use ergotree_ir::mir::expr::Expr;
    use ergotree_ir::mir::global_vars::GlobalVars;
    use ergotree_ir::mir::unary_op::OneArgOpTryBuild;
    use sigma_test_util::force_any_val;

    use super::*;

    #[test]
    fn eval() {
        let expr: Expr = ExtractCreationInfo::try_build(GlobalVars::SelfBox.into())
            .unwrap()
            .into();
        let ctx = force_any_val::<Context>();
        let v = eval_out::<(i32, Vec<i8>)>(&expr, &ctx);
        assert_eq!(v, ctx.self_box.creation_info());
    }
}
