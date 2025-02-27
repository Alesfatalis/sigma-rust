use core::convert::TryInto;

use alloc::vec::Vec;

use crate::serialization::op_code::OpCode;
use crate::serialization::sigma_byte_reader::SigmaByteRead;
use crate::serialization::sigma_byte_writer::SigmaByteWrite;
use crate::serialization::SigmaParsingError;
use crate::serialization::SigmaSerializable;
use crate::serialization::SigmaSerializeResult;
use crate::traversable::impl_traversable_expr;
use crate::types::stuple::STuple;
use crate::types::stuple::TupleItems;
use crate::types::stype::SType;

use super::expr::Expr;
use super::expr::InvalidArgumentError;
use crate::has_opcode::HasStaticOpCode;

/// Tuple of elements
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct Tuple {
    /// Tuple items
    pub items: TupleItems<Expr>,
}

impl Tuple {
    /// Create new object
    pub fn new(items: Vec<Expr>) -> Result<Self, InvalidArgumentError> {
        Ok(Tuple {
            items: items.try_into()?,
        })
    }

    /// Type
    pub fn tpe(&self) -> SType {
        SType::STuple(STuple {
            items: self.items.mapped_ref(|it| it.tpe()),
        })
    }
}

impl HasStaticOpCode for Tuple {
    const OP_CODE: OpCode = OpCode::TUPLE;
}

impl SigmaSerializable for Tuple {
    fn sigma_serialize<W: SigmaByteWrite>(&self, w: &mut W) -> SigmaSerializeResult {
        w.put_u8(self.items.len() as u8)?;
        self.items.iter().try_for_each(|i| i.sigma_serialize(w))
    }

    fn sigma_parse<R: SigmaByteRead>(r: &mut R) -> Result<Self, SigmaParsingError> {
        let items_count = r.get_u8()?;
        let mut items = Vec::with_capacity(items_count as usize);
        for _ in 0..items_count {
            items.push(Expr::sigma_parse(r)?);
        }
        Ok(Tuple {
            items: items.try_into()?,
        })
    }
}

impl_traversable_expr!(Tuple, arr items);

#[cfg(feature = "arbitrary")]
#[allow(clippy::unwrap_used)]
/// Arbitrary impl
mod arbitrary {

    use super::*;
    use crate::mir::constant::Constant;
    use proptest::collection::*;
    use proptest::prelude::*;

    impl Arbitrary for Tuple {
        type Strategy = BoxedStrategy<Self>;
        type Parameters = ();

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            prop_oneof![
                vec(any::<Expr>(), 2..4),
                vec(any::<Constant>().prop_map_into(), 2..4)
            ]
            .prop_map(move |items| Self::new(items).unwrap())
            .boxed()
        }
    }
}

#[cfg(test)]
#[cfg(feature = "arbitrary")]
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use crate::serialization::sigma_serialize_roundtrip;
    use proptest::prelude::*;

    proptest! {

        #[test]
        fn ser_roundtrip(v in any::<Tuple>()) {
            let expr: Expr = v.into();
            prop_assert_eq![sigma_serialize_roundtrip(&expr), expr];
        }

    }
}
