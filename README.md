***Author: Patrick Singh***

# Integration of vTPMs into Chromium with the Web Crypto API

A master's thesis project at **TU Darmstadt** implementing **virtual Trusted Platform Module (vTPM) integration** into Chromium's Web Cryptography API, enabling hardware-backed key storage and cryptographic operations directly in web browsers.

## 🔒 Project Overview

This project modifies Chromium's source code to integrate IBM's software TPM implementation as a secure key storage backend for the Web Crypto API. Instead of storing cryptographic keys in browser memory or IndexedDB, all private keys are securely managed by a virtual TPM, providing hardware-level security guarantees for web applications.

## 🏗️ Architecture

The integration intercepts Chromium's Web Crypto API implementation at the key storage layer, redirecting key operations to a running vTPM instance:

```
Website (JavaScript)
       ↓
Web Crypto API Call (crypto.subtle.*)
       ↓
Chromium Web Crypto Implementation
       ↓
Modified Key Storage Layer
       ↓ 
IBM vTPM (Key Management & Crypto Operations)
```

### Key Components

- **Modified Chromium Source**: Custom modifications to Web Crypto key storage mechanisms
- **IBM TPM Implementation**: Software-based TPM 2.0 compliant virtual TPM
- **Key Storage Backend**: TPM-backed secure key storage replacing default browser storage
- **Crypto Operations Pipeline**: Direct TPM integration for encrypt/decrypt/sign/verify operations

## ✨ Features

### Supported Web Crypto Operations
- ✅ **Key Generation**: Generate cryptographic keys directly in vTPM
- ✅ **Encrypt/Decrypt**: TPM-backed symmetric and asymmetric encryption
- ✅ **Sign/Verify**: Digital signatures using TPM-protected keys
- ✅ **Key Export**: Controlled key export with TPM security policies
- ✅ **Key Import**: Import external keys into TPM secure storage

### Security Benefits
- **Hardware-Level Security**: Keys never exist in plaintext outside the TPM
- **Tamper Resistance**: TPM-based key protection against software attacks
- **Secure Key Storage**: Persistent key storage with TPM security guarantees
- **Attestation Ready**: Foundation for TPM-based remote attestation
- **Memory Protection**: Keys isolated from browser process memory

## 🚀 Quick Start

### Prerequisites
- Linux development environment
- Chromium build dependencies
- IBM TPM simulator dependencies

### Installation & Build

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Singheskan/Integration-of-vTPMs-into-Chromium-with-the-Web-Crypto-API.git
   cd Integration-of-vTPMs-into-Chromium-with-the-Web-Crypto-API
   ```

2. **Build Chromium with vTPM integration:**
   ```bash
   # Run the build script
   ./build.sh
   ```

3. **Start the IBM TPM simulator:**
   ```bash
   # Run the TPM startup script
   ./start_tpm.sh
   ```

4. **Launch modified Chromium:**
   ```bash
   # The build script will create a modified Chromium binary
   ./out/Release/chrome
   ```

## 💻 Usage Examples

### Basic Web Crypto with vTPM Backend

```javascript
// Generate an RSA key pair - keys stored in vTPM
crypto.subtle.generateKey(
  {
    name: "RSASSA-PKCS1-v1_5",
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: "SHA-256"
  },
  false, // extractable
  ["sign", "verify"]
).then(keyPair => {
  console.log("Keys generated and stored in vTPM");
  // Private key is securely stored in vTPM
  return crypto.subtle.sign("RSASSA-PKCS1-v1_5", keyPair.privateKey, data);
});
```

### Encryption with TPM-backed Keys

```javascript
// AES key generation with vTPM storage
crypto.subtle.generateKey(
  { name: "AES-GCM", length: 256 },
  false, // non-extractable - secured by TPM
  ["encrypt", "decrypt"]
).then(key => {
  // Key is stored in vTPM, encrypt operation uses TPM
  return crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    key,
    plaintext
  );
});
```

## 🔧 Technical Implementation

### Modified Chromium Components

- **`blink/renderer/modules/crypto/`**: Web Crypto API JavaScript bindings
- **`components/webcrypto/`**: Core WebCrypto implementation
- **`third_party/blink/renderer/modules/crypto/`**: Crypto key management
- **Custom TPM Backend**: Integration layer for IBM TPM communication

### Key Storage Flow

1. **Web Crypto API Call**: JavaScript calls `crypto.subtle.generateKey()`
2. **Blink Processing**: Request processed through Blink's crypto modules
3. **Key Generation**: Modified backend generates keys via TPM
4. **Secure Storage**: Private keys stored exclusively in vTPM
5. **Handle Return**: Only key handles returned to JavaScript context

### TPM Integration Details

- **TPM 2.0 Compliance**: Uses IBM's TPM 2.0 specification implementation
- **Key Hierarchy**: Implements proper TPM key hierarchy and storage
- **Persistent Handles**: Keys persist across browser sessions via TPM NVRAM
- **Access Control**: TPM-enforced access policies for key operations

## 📊 Performance Considerations

- **Latency**: Additional TPM communication adds ~10-50ms per operation
- **Throughput**: Bulk operations benefit from TPM's hardware acceleration
- **Memory**: Reduced browser memory usage (keys stored in TPM)
- **Security vs Speed**: Trade-off favors security over raw performance

## 🧪 Testing & Examples

The repository includes comprehensive examples demonstrating vTPM integration:

### Available Test Cases
- **Key Generation Examples**: RSA, ECDSA, AES key generation
- **Encryption/Decryption Tests**: Various algorithms with TPM backend
- **Digital Signature Examples**: Sign/verify operations using TPM keys
- **Key Import/Export Tests**: Controlled key material handling
- **Cross-Session Persistence**: Key availability across browser restarts

### Running Examples
```bash
# Start Chromium with test pages
./chrome --enable-features=WebCrypto file://path/to/examples/
```

## 🔬 Research Context

### Master's Thesis Contributions

1. **Novel Architecture**: First integration of vTPM with browser Web Crypto API
2. **Security Enhancement**: Hardware-level key protection for web applications
3. **Practical Implementation**: Working proof-of-concept with real TPM backend
4. **Performance Analysis**: Comprehensive evaluation of security vs performance trade-offs

### Academic Significance

- **Web Security**: Advances browser-based cryptographic security
- **TPM Applications**: Demonstrates practical TPM usage in web contexts
- **Standards Compliance**: Maintains W3C Web Crypto API compatibility
- **Future Research**: Foundation for hardware-backed web security

## 🛠️ Development

### Project Structure
```
├── chromium/                    # Modified Chromium source files
│   ├── blink/                  # Web Crypto API modifications
│   ├── components/webcrypto/   # Core crypto implementation
│   └── third_party/           # TPM integration layer
├── tpm/                        # IBM TPM configuration and scripts
├── examples/                   # Web Crypto demonstration pages
├── build.sh                    # Chromium build script
├── start_tpm.sh               # TPM simulator startup
└── docs/                      # Technical documentation
```

### Build Configuration

The build process:
1. Patches Chromium source with vTPM integration
2. Configures build system for TPM dependencies
3. Compiles modified Chromium with vTPM backend
4. Sets up TPM simulator environment

### Debugging

- **TPM Logs**: Monitor TPM operations via simulator output
- **Chrome DevTools**: Standard web debugging with crypto operations
- **Debug Builds**: Additional logging for crypto/TPM integration
- **Trace Analysis**: Performance profiling of TPM operations

## ⚠️ Limitations & Future Work

### Current Limitations
- **Algorithm Support**: Limited to specific crypto algorithms
- **Platform Support**: Linux-only implementation
- **Performance**: TPM communication overhead
- **Single TPM**: One TPM instance per browser session

### Future Enhancements
- **Algorithm Expansion**: Support for additional Web Crypto algorithms
- **Multi-Platform**: Windows and macOS support
- **Hardware TPM**: Integration with physical TPM devices
- **Remote Attestation**: TPM-based web application attestation
- **Performance Optimization**: Caching and batching strategies

## 📚 Technical References

### Standards & Specifications
- [W3C Web Cryptography API](https://www.w3.org/TR/WebCryptoAPI/)
- [TPM 2.0 Specification](https://trustedcomputinggroup.org/tpm-library-specification/)
- [IBM TPM 2.0 TSS](https://sourceforge.net/projects/ibmtpm20tss/)

### Related Research
- Trusted Platform Module applications in web security
- Browser-based hardware security module integration
- Web Crypto API security analysis and enhancements

## 🤝 Contributing

This is a research project completed as part of a master's thesis. While the main development is complete, contributions for:

- Additional algorithm support
- Platform compatibility
- Performance improvements
- Security analysis

are welcome for future research directions.

## 📄 License

This project modifies Chromium source code and includes IBM TPM implementation. Please refer to individual component licenses:
- Chromium: [BSD-style license](https://chromium.googlesource.com/chromium/src/+/master/LICENSE)
- IBM TPM: [IBM TPM License](https://sourceforge.net/projects/ibmtpm20tss/)

## 📞 Contact

**Patrick Singh**
- GitHub: [@Singheskan](https://github.com/Singheskan)
- Email: [Contact for research inquiries]

---

**Academic Context**: This project was completed as part of a Master's thesis on "Integration of Virtual Trusted Platform Modules into Web Browsers using the Web Cryptography API" at **TU Darmstadt** - demonstrating practical application of hardware security concepts in modern web development.

**Research Impact**: This work contributes to the field of web security by providing a practical implementation of hardware-backed cryptographic operations in web browsers, paving the way for more secure web applications.
