use crate::ergo_tree::ErgoTreeVersion;
use crate::serialization::types::TypeCode;
use crate::types::stuple::STuple;
use crate::types::stype_companion::STypeCompanion;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use super::sfunc::SFunc;
use super::smethod::MethodId;
use super::smethod::SMethod;
use super::smethod::SMethodDesc;
use super::stype::SType;
use super::stype_param::STypeVar;
use lazy_static::lazy_static;

/// SColl type code
pub const TYPE_CODE: TypeCode = TypeCode::COLL;
/// SColl type name
pub static TYPE_NAME: &str = "Coll";
/// Coll.indexOf
pub const INDEX_OF_METHOD_ID: MethodId = MethodId(26);
/// Coll.flatmap
pub const FLATMAP_METHOD_ID: MethodId = MethodId(15);
/// Coll.zip
pub const ZIP_METHOD_ID: MethodId = MethodId(29);
/// Coll.indices
pub const INDICES_METHOD_ID: MethodId = MethodId(14);
/// Coll.patch
pub const PATCH_METHOD_ID: MethodId = MethodId(19);
/// Coll.updated
pub const UPDATED_METHOD_ID: MethodId = MethodId(20);
/// Coll.updateMany
pub const UPDATE_MANY_METHOD_ID: MethodId = MethodId(21);

lazy_static! {
    /// Coll method descriptors
    pub(crate) static ref METHOD_DESC: Vec<&'static SMethodDesc> =
        vec![
            &INDEX_OF_METHOD_DESC,
            &FLATMAP_METHOD_DESC,
            &ZIP_METHOD_DESC,
            &INDICES_METHOD_DESC,
            &UPDATED_METHOD_DESC,
            &UPDATE_MANY_METHOD_DESC,
            &PATCH_METHOD_DESC,
        ]
    ;
}

lazy_static! {
    static ref INDEX_OF_METHOD_DESC: SMethodDesc = SMethodDesc {
        method_id: INDEX_OF_METHOD_ID,
        name: "indexOf",
        tpe: SFunc {
            t_dom: vec![
                SType::SColl(SType::STypeVar(STypeVar::t()).into()),
                STypeVar::t().into(),
                SType::SInt],
            t_range: SType::SInt.into(),
            tpe_params: vec![],
        },
        explicit_type_args: vec![],
        min_version: ErgoTreeVersion::V0
    };
    /// Coll.indexOf
    pub static ref INDEX_OF_METHOD: SMethod = SMethod::new(STypeCompanion::Coll, INDEX_OF_METHOD_DESC.clone());
}

lazy_static! {
    static ref FLATMAP_METHOD_DESC: SMethodDesc = SMethodDesc {
        method_id: FLATMAP_METHOD_ID,
        name: "flatMap",
        tpe: SFunc::new(
            vec![
                SType::SColl(SType::STypeVar(STypeVar::iv()).into()),
                SFunc::new(
                    vec![STypeVar::iv().into()],
                    SType::SColl(Arc::new(STypeVar::ov().into())),
                ).into()
                ],
            SType::SColl(SType::STypeVar(STypeVar::ov()).into()),
        ),
        explicit_type_args: vec![],
        min_version: ErgoTreeVersion::V0
    };
    /// Coll.flatMap
    pub static ref FLATMAP_METHOD: SMethod = SMethod::new(STypeCompanion::Coll, FLATMAP_METHOD_DESC.clone());
}

lazy_static! {
    static ref ZIP_METHOD_DESC: SMethodDesc = SMethodDesc {
        method_id: ZIP_METHOD_ID,
        name: "zip",
        tpe: SFunc::new(
            vec![
                SType::SColl(SType::STypeVar(STypeVar::t()).into()),
                SType::SColl(SType::STypeVar(STypeVar::iv()).into())
            ],
            SType::SColl(SType::STuple(STuple::pair(
                STypeVar::t().into(), STypeVar::iv().into()
            )).into())
        ),
        explicit_type_args: vec![],
        min_version: ErgoTreeVersion::V0
    };
    /// Coll.zip
    pub static ref ZIP_METHOD: SMethod = SMethod::new(STypeCompanion::Coll, ZIP_METHOD_DESC.clone());
}

lazy_static! {
    static ref INDICES_METHOD_DESC: SMethodDesc = SMethodDesc {
        method_id: INDICES_METHOD_ID,
        name: "indices",
        tpe: SFunc::new(
            vec![
                SType::SColl(SType::STypeVar(STypeVar::t()).into()),
            ],
            SType::SColl(SType::SInt.into())
        ),
        explicit_type_args: vec![],
        min_version: ErgoTreeVersion::V0
    };
    /// Coll.indices
    pub static ref INDICES_METHOD: SMethod = SMethod::new(STypeCompanion::Coll, INDICES_METHOD_DESC.clone());
}

lazy_static! {
    static ref PATCH_METHOD_DESC: SMethodDesc = SMethodDesc {
        method_id: PATCH_METHOD_ID,
        name: "patch",
        tpe: SFunc::new(
            vec![
                SType::SColl(SType::STypeVar(STypeVar::t()).into()),
                SType::SInt,
                SType::SColl(SType::STypeVar(STypeVar::t()).into()),
                SType::SInt,
            ],
            SType::SColl(SType::STypeVar(STypeVar::t()).into())
        ),
        explicit_type_args: vec![],
        min_version: ErgoTreeVersion::V0
    };
    /// Coll.patch
    pub static ref PATCH_METHOD: SMethod = SMethod::new(STypeCompanion::Coll, PATCH_METHOD_DESC.clone());
}

lazy_static! {
    static ref UPDATED_METHOD_DESC: SMethodDesc = SMethodDesc {
        method_id: UPDATED_METHOD_ID,
        name: "updated",
        tpe: SFunc::new(
            vec![
                SType::SColl(SType::STypeVar(STypeVar::t()).into()),
                SType::SInt,
                SType::STypeVar(STypeVar::t())

            ],
            SType::SColl(SType::STypeVar(STypeVar::t()).into())
        ),
        explicit_type_args: vec![],
        min_version: ErgoTreeVersion::V0
    };
    /// Coll.updated
    pub static ref UPDATED_METHOD: SMethod = SMethod::new(STypeCompanion::Coll, UPDATED_METHOD_DESC.clone());
}

lazy_static! {
    static ref UPDATE_MANY_METHOD_DESC: SMethodDesc = SMethodDesc {
        method_id: UPDATE_MANY_METHOD_ID,
        name: "updateMany",
        tpe: SFunc::new(
            vec![
                SType::SColl(SType::STypeVar(STypeVar::t()).into()),
                SType::SColl(SType::SInt.into()),
                SType::SColl(SType::STypeVar(STypeVar::t()).into())

            ],
            SType::SColl(SType::STypeVar(STypeVar::t()).into())
        ),
        explicit_type_args: vec![],
        min_version: ErgoTreeVersion::V0
    };
    /// Coll.updateMany
    pub static ref UPDATE_MANY_METHOD: SMethod = SMethod::new(STypeCompanion::Coll, UPDATE_MANY_METHOD_DESC.clone());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_ids() {
        assert!(
            SMethod::from_ids(TYPE_CODE, INDEX_OF_METHOD_ID).map(|e| e.name()) == Ok("indexOf")
        );
        assert!(SMethod::from_ids(TYPE_CODE, FLATMAP_METHOD_ID).map(|e| e.name()) == Ok("flatMap"));
        assert!(SMethod::from_ids(TYPE_CODE, ZIP_METHOD_ID).map(|e| e.name()) == Ok("zip"));
        assert!(SMethod::from_ids(TYPE_CODE, INDICES_METHOD_ID).map(|e| e.name()) == Ok("indices"));
        assert!(SMethod::from_ids(TYPE_CODE, PATCH_METHOD_ID).map(|e| e.name()) == Ok("patch"));
        assert!(SMethod::from_ids(TYPE_CODE, UPDATED_METHOD_ID).map(|e| e.name()) == Ok("updated"));
        assert!(
            SMethod::from_ids(TYPE_CODE, UPDATE_MANY_METHOD_ID).map(|e| e.name())
                == Ok("updateMany")
        );
    }
}
