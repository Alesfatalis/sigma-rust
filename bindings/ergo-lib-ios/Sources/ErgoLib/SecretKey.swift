import Foundation
import ErgoLibC

struct SecretKeyError: Error {}
/// Secret key for the prover
class SecretKey {
    internal var pointer: SecretKeyPtr
    
    /// Generate random key
    init() {
        var ptr: SecretKeyPtr?
        ergo_lib_secret_key_generate_random(&ptr)
        self.pointer = ptr!
    }
    
    /// Parse dlog secret key from bytes (SEC-1-encoded scalar)
    init(fromBytes : [UInt8]) throws {
        var ptr: SecretKeyPtr?
        if fromBytes.count != 32 {
            throw SecretKeyError()
        }
        let error = ergo_lib_secret_key_from_bytes(fromBytes, &ptr)
        try checkError(error)
        self.pointer = ptr!
    }
    
    /// Takes ownership of an existing ``SecretKeyPtr``. Note: we must ensure that no other instance
    /// of ``SecretKey`` can hold this pointer.
    internal init(withRawPointer ptr: BlockHeaderPtr) {
        self.pointer = ptr
    }
    
    /// Get address (encoded public image)
    func getAddress() -> Address {
        var ptr: AddressPtr?
        ergo_lib_secret_key_get_address(self.pointer, &ptr)
        return Address(withRawPointer: ptr!)
    }
    
    /// Encode to bytes.
    func toBytes() -> [UInt8] {
        var bytes = Array.init(repeating: UInt8(0), count: 32)
        ergo_lib_secret_key_to_bytes(self.pointer, &bytes)
        return bytes
    }
    
    deinit {
        ergo_lib_secret_key_delete(self.pointer)
    }
}

/// An ordered collection of ``SecretKey``s
class SecretKeys {
    internal var pointer: SecretKeysPtr
    
    /// Create an empty collection
    init() {
        var ptr: SecretKeysPtr?
        ergo_lib_secret_keys_new(&ptr)
        self.pointer = ptr!
    }
    
    /// Return the length of the collection
    func len() -> UInt {
        return ergo_lib_secret_keys_len(self.pointer)
    }
    
    /// Returns the ``SecretKey`` at location `index` if it exists.
    func get(index: UInt) -> SecretKey? {
        var ptr: SecretKeyPtr?
        let res = ergo_lib_secret_keys_get(self.pointer, index, &ptr)
        assert(res.error == nil)
        if res.is_some {
            return SecretKey(withRawPointer: ptr!)
        } else {
            return nil
        }
    }
    
    /// Add a ``SecretKey`` to the end of the collection.
    func add(secretKey: SecretKey) {
        ergo_lib_secret_keys_add(secretKey.pointer, self.pointer)
    }
        
    deinit {
        ergo_lib_secret_keys_delete(self.pointer)
    }
}
