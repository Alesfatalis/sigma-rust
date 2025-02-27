use crate::constant::{ConstConstantPtr, Constant, ConstantPtr};
use crate::{
    util::{const_ptr_as_ref, mut_ptr_as_mut},
    Error,
};
use ergo_lib::ergotree_ir::chain::context_extension;

/// User-defined variables to be put into context
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct ContextExtension(pub context_extension::ContextExtension);
pub type ContextExtensionPtr = *mut ContextExtension;
pub type ConstContextExtensionPtr = *const ContextExtension;

/// Create new empty ContextExtension instance
pub unsafe fn context_extension_empty(
    context_extension_out: *mut ContextExtensionPtr,
) -> Result<(), Error> {
    let context_extension_out = mut_ptr_as_mut(context_extension_out, "context_extension_out")?;
    *context_extension_out = Box::into_raw(Box::new(ContextExtension(
        context_extension::ContextExtension::empty(),
    )));
    Ok(())
}

/// Returns the number of elements in the collection
pub unsafe fn context_extension_len(
    context_extension_ptr: ConstContextExtensionPtr,
) -> Result<usize, Error> {
    let context_extension = const_ptr_as_ref(context_extension_ptr, "context_extension_ptr")?;
    Ok(context_extension.0.values.len())
}

/// Returns all keys (represented as u8 values) in the map
pub unsafe fn context_extension_keys(
    context_extension_ptr: ConstContextExtensionPtr,
    output: *mut u8,
) -> Result<(), Error> {
    let context_extension = const_ptr_as_ref(context_extension_ptr, "context_extension_ptr")?;
    let src: Vec<_> = context_extension.0.values.keys().cloned().collect();
    std::ptr::copy_nonoverlapping(src.as_ptr(), output, src.len());
    Ok(())
}

/// Get value for key or fail if key is missing
pub unsafe fn context_extension_get(
    context_extension_ptr: ConstContextExtensionPtr,
    key: u8,
    constant_out: *mut ConstantPtr,
) -> Result<bool, Error> {
    let context_extension = const_ptr_as_ref(context_extension_ptr, "context_extension_ptr")?;
    let constant_out = mut_ptr_as_mut(constant_out, "constant_out")?;
    let constant = context_extension
        .0
        .values
        .get(&key)
        .map(|c| Constant(c.clone()));

    if let Some(constant) = constant {
        *constant_out = Box::into_raw(Box::new(constant));
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Set the supplied pair in the ContextExtension
pub unsafe fn context_extension_set_pair(
    constant_ptr: ConstConstantPtr,
    key: u8,
    context_extension_ptr: ContextExtensionPtr,
) -> Result<(), Error> {
    let constant = const_ptr_as_ref(constant_ptr, "constant_ptr")?;
    let context_extension = mut_ptr_as_mut(context_extension_ptr, "context_extension_ptr")?;
    context_extension.0.values.insert(key, constant.0.clone());
    Ok(())
}
