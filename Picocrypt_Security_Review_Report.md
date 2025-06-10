# Picocrypt v1.48 Security Code Review Report

## 1. Introduction

This report summarizes the findings of a security code review conducted on the Picocrypt v1.48 application. The review focused on the Go source code (`src/Picocrypt.go`) and associated build/distribution files available in the repository. The goal was to identify potential security vulnerabilities, assess the soundness of cryptographic implementations, and provide recommendations for improvement.

## 2. Overall Security Posture

Picocrypt demonstrates a strong commitment to security in its design and implementation. The core cryptographic operations are generally sound, leveraging modern, robust algorithms and practices. The code is self-contained in a single Go file for its core logic, which aids review. Error handling is present, and the lack of verbose file logging is a plus. The Plausible Deniability and Reed-Solomon features are notable additions with specific security characteristics.

No critical vulnerabilities that would allow for immediate compromise of the core encryption under typical usage were identified in the reviewed code. The recommendations primarily focus on defense-in-depth, supply chain security for the build process, and clarification of advanced feature behavior.

## 3. Key Findings by Area

### 3.1. Cryptographic Primitives & Usage
*   **Strong Choices:** Uses Argon2id for key derivation, ChaCha20 and Serpent (optional "Paranoid" mode) for encryption, HMAC-SHA3-512 or Keyed BLAKE2b for MAC, SHA3 for hashing, and HKDF for subkey derivation. These are excellent, modern choices.
*   **Parameters:** Salts (16-byte Argon2, 32-byte HKDF), nonces (24-byte ChaCha20), and IVs (16-byte Serpent) are generated using `crypto/rand` and are of appropriate lengths. Argon2 parameters are robust (1GiB memory, 4-8 iterations).
*   **Nonce/IV Rekeying:** For large files (>60GiB), nonces/IVs for the main encryption are updated using HKDF from the master key, which is a sound approach. The Plausible Deniability layer uses a different SHA3-based nonce update for its outer encryption if the volume is large; while non-standard, it's likely secure in context given the unique key and initial random nonce for that layer.
*   **Temporary Zip Encryption:** Uses unauthenticated ChaCha20 for an intermediate zip file during multi-file operations. The risk is likely low as it's a local temporary file and the main subsequent encryption is authenticated.

### 3.2. Key Management
*   Keys are derived on-the-fly from passwords (Argon2id) and optional keyfiles; they are not stored persistently.
*   Keyfiles are processed by hashing their content with SHA3-256 and then XORing the resulting hash (or a combination of hashes if multiple keyfiles) with the password-derived key. This combination method is sound. Checks for all-zero effective keyfile contributions (e.g., from duplicate unordered keyfiles) are present.
*   Password handling includes UI masking, clearing from memory via a comprehensive `resetUI()` function, and strength estimation with `zxcvbn-go`. Clipboard copy/paste of passwords is a user-initiated action with inherent OS-level risks.
*   Necessary salts and verification hashes (`keyHashRef` for password, `keyfileHashRef` for keyfiles) are stored in the file header to enable decryption and verification.

### 3.3. Input Validation & Handling
*   User comments have a defined length limit. Numeric inputs (e.g., `splitSize` for file chunking) are validated.
*   Zip file extraction (`unpackArchive` function) includes a `strings.Contains(f.Name, "..")` check on archive member names to prevent basic Zip Slip path traversal vulnerabilities.

### 3.4. File I/O Operations
*   The use of `.incomplete` temporary files for output and subsequent `os.Rename` on success promotes atomicity for write operations, reducing risk of data corruption from interruptions.
*   Temporary files created during intermediate steps (e.g., temporary zip, plausible deniability processing) are generally cleaned up correctly on success, error, or cancellation.
*   File handles are mostly closed explicitly. More consistent use of `defer file.Close()` could improve code robustness for future modifications.

### 3.5. Error Handling & Logging
*   User-facing error messages, displayed in the UI status area, are generally clear and do not appear to leak sensitive cryptographic data or excessive system details.
*   No file-based logging was found within `Picocrypt.go`, which is positive from a security standpoint as it avoids persistent storage of potentially sensitive operational data.
*   `panic()` is used for conditions deemed fatal by the application, primarily unexpected errors from cryptographic libraries or critical I/O operations. Panic messages are generally generic.

### 3.6. Plausible Deniability
*   Implemented as an outer encryption layer (Argon2/ChaCha20 with its own unique random salt and nonce) applied over a standard Picocrypt volume.
*   If the correct password for this outer layer is not supplied, the file content (after the initial salt/nonce) will appear as random data, thus providing deniability against casual observation or tools that expect specific file signatures.
*   **Limitation:** The current implementation uses the *same user-provided password* to decrypt the outer Plausible Deniability layer and subsequently to derive the key for the inner (actual) volume. It does not support a distinct "hidden volume password" separate from the "outer volume password". The UI tooltip appropriately warns users about this feature.

### 3.7. Reed-Solomon Erasure Coding
*   Effectively utilized with high redundancy (e.g., 1 data byte to 3 total bytes for comments, 5 data to 15 total for version) to protect all critical header fields against corruption. This significantly enhances volume robustness.
*   Optionally, it can be applied to the ciphertext of the main file data with lower redundancy (128 data bytes, 8 parity bytes, correcting up to 4 corrupted bytes per 136-byte block).
*   The `fastDecode` optimization (skipping RS decoding if MAC verifies) is a sensible performance enhancement. PKCS#7 padding for the final data block (if RS coding is active for data) is correctly handled.

### 3.8. Dependency Review
*   Core cryptographic operations leverage Go's standard `crypto/*` packages and the supplementary `golang.org/x/crypto` library (v0.38.0 at the time of review, which is reasonably recent).
*   Several custom libraries from `github.com/Picocrypt/*` are used for:
    *   **Serpent cipher:** `github.com/Picocrypt/serpent` (critical for confidentiality).
    *   **Reed-Solomon:** `github.com/Picocrypt/infectious`.
    *   **GUI:** `github.com/Picocrypt/giu` (and its underlying `imgui-go` bindings).
    *   **Dialogs:** `github.com/Picocrypt/dialog`.
    *   **Password Strength:** `github.com/Picocrypt/zxcvbn-go`.
*   The security of Picocrypt is inherently tied to the security and correctness of these custom dependencies.

### 3.9. Concurrency and Goroutines
*   Goroutines are employed for background tasks (file scanning, encryption/decryption) to maintain UI responsiveness.
*   Synchronization primarily relies on disabling UI elements during operations, cooperative cancellation checks (via the `working` flag), and the `giu.Update()` mechanism (assumed to handle thread-safe UI updates).
*   While explicit Go mutexes are not used for most global state variables shared between worker goroutines and the main GUI thread, the typical immediate-mode GUI update pattern likely mitigates many direct data race potentials for UI data.
*   Recursive operations correctly scope their operational parameters, reducing risks of self-interference. No critical race conditions directly compromising cryptographic integrity were found.

### 3.10. GUI Interaction and State Management
*   Sensitive inputs like passwords are appropriately masked in UI fields by default.
*   The `resetUI()` function is critical and implemented diligently to clear sensitive global variables (passwords, keyfiles, operational state) after operations or on user request. This is key to preventing state leakage.
*   The clipboard copy feature for passwords, while a common usability function, carries inherent OS-level risks that users should be aware of.

### 3.11. Build and Distribution
*   Builds are automated via GitHub Actions for Linux, macOS, and Windows.
*   CodeQL static analysis is integrated into CI, a positive security measure.
*   Official releases include SHA256 checksums for artifact verification by users.
*   **Supply Chain Concern:** Build-time tools (Resource Hacker, UPX) and a .deb packaging skeleton are downloaded from `github.com/user-attachments` URLs during CI builds. This practice poses a supply chain risk if the content at these URLs is compromised.

## 4. Security Recommendations

### 4.1. High Priority
*   **Audit Custom Serpent Implementation (`github.com/Picocrypt/serpent`):**
    *   **Recommendation:** Given that Serpent is a less common cipher than AES, and cryptographic implementations are notoriously difficult to get right, the custom `github.com/Picocrypt/serpent` library should ideally undergo a dedicated, expert cryptographic audit. This is paramount for ensuring the confidentiality provided by Picocrypt when Serpent is in use (Paranoid mode).
    *   **Rationale:** Flaws in cipher implementations can lead to catastrophic vulnerabilities.

### 4.2. Medium Priority
*   **Build Process Hardening - Vendor/Verify Build Tools:**
    *   **Recommendation:** Modify the GitHub Actions workflows to avoid downloading build-time dependencies (Resource Hacker, UPX, .deb skeleton ZIP) from `user-attachments` URLs. Instead:
        1.  Commit these tools/templates directly into the Picocrypt repository (e.g., under a `build_tools/` directory).
        2.  Alternatively, if fetching from official sources, ensure their checksums are programmatically verified within the build script immediately after download and before execution/use.
    *   **Rationale:** This mitigates the supply chain risk of the build process being compromised if the externally hosted files are tampered with.

### 4.3. Low Priority / Considerations
*   **Plausible Deniability Password Clarification:**
    *   **Recommendation:** Enhance documentation to explicitly state that the current Plausible Deniability feature uses the *same* password for the outer decoy layer and the inner volume's decryption. This manages user expectations, as it differs from "hidden volume with a separate password" schemes found in some other tools.
    *   **Rationale:** Clear documentation prevents user misunderstanding of the feature's capabilities.
*   **Clipboard Interaction Risks:**
    *   **Recommendation:** Briefly remind users in the documentation about the general security risks associated with using the clipboard for sensitive data like passwords.
    *   **Rationale:** User education on a common but potentially risky OS feature.
*   **File Closing Consistency:**
    *   **Recommendation:** Consider more consistent use of `defer file.Close()` immediately after `os.Open` or `os.Create` calls, particularly in the `work()` function and its helper routines.
    *   **Rationale:** While current explicit `Close()` calls appear to cover necessary paths, `defer` simplifies logic, reduces the chance of missed closes if new code paths are added, and is idiomatic Go.
*   **Zip Slip Defense-in-Depth (Minor Enhancement):**
    *   **Recommendation:** In the `unpackArchive` function, after `outPath := filepath.Join(extractDir, f.Name)`, consider adding an explicit check to ensure that the cleaned, absolute `outPath` is still a child of (or prefixed by) the cleaned, absolute `extractDir`.
    *   **Rationale:** Provides an additional layer of defense against more sophisticated or unusual Zip Slip path traversal attempts that might bypass the current `strings.Contains(f.Name, "..")` check.

## 5. Conclusion

Picocrypt v1.48 is a thoughtfully designed piece of encryption software with a strong emphasis on modern cryptographic practices. The core encryption and key derivation logic appears sound. The provided recommendations aim to further enhance its security, particularly in the areas of dependency trust and build process integrity.
