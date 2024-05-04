import Foundation
import ErgoLibC

class ExtSecretKey {
    internal var pointer: ExtSecretKeyPtr

    /// Create ExtSecretKey from secret key bytes, chain code and derivation path
    init(secretKeyBytes: [UInt8], chainCodeBytes: [UInt8], derivationPath: DerivationPath) throws {
        var ptr: ExtSecretKeyPtr?
        let error = ergo_lib_ext_secret_key_new(secretKeyBytes, chainCodeBytes, derivationPath.pointer, &ptr)
        try checkError(error)
        self.pointer = ptr!
    }

    /// Derive root extended secret key from seed bytes
    init(seedBytes: [UInt8]) throws {
        var ptr: ExtSecretKeyPtr?
        let error = ergo_lib_ext_secret_key_derive_master(seedBytes, &ptr)
        try checkError(error)
        self.pointer = ptr!
    }

    /// Takes ownership of an existing ```ExtSecretKeyPtr```
    internal init(withRawPointer ptr: ExtSecretKeyPtr) {
        self.pointer = ptr
    }

    /// Derive a new extended secret key from the provided index
    /// The index is in the form of soft or hardened indices
    /// For example: 4 or 4' respectively
    func child(indexStr: String) throws -> ExtSecretKey {
        var ptr: ExtSecretKeyPtr?
        let error = indexStr.withCString { cs in
            ergo_lib_ext_secret_key_child(self.pointer, cs, &ptr)
        }
        try checkError(error)
        return ExtSecretKey(withRawPointer: ptr!)
    }

    deinit {
        ergo_lib_ext_secret_key_delete(self.pointer)
    }
}
