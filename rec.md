### Summary of Findings

1. **PCC-001**
   - **Type:** Design decision
   - **Description:** Data encrypted with Picocrypt is stored in a custom file format, including a header which is unauthenticated. As a result, any changes made by an attacker would go undetected.
   - **Threat level:** Low

2. **PCC-004**
   - **Type:** Cryptographic implementation
   - **Description:** Picocrypt offers both encryption and authentication. When a user wants to decrypt a volume, it starts with decrypting and only verifies the signature afterwards. As a result a user may unknowingly use their private key on attacker-controlled material.
   - **Threat level:** Low

3. **PCC-006**
   - **Type:** Design decision
   - **Description:** Picocrypt uses a memory-hard key derivation function to limit brute force attacks on the password. The output is then hashed using SHA3-512 and stored in the header, to verify the key before attempting to decrypt. As a result there are two algorithms that can be attacked individually which would both lead to the key.
   - **Threat level:** N/A

### Summary of Recommendations

1. **PCC-001**
   - **Type:** Design decision
   - **Recommendation:**
     - Authenticate data before processing. Since part of the header is required for key derivation, this is not possible. Adding authentication to the header would allow users to be informed if the header was tampered with (after key derivation, but before decryption).

2. **PCC-004**
   - **Type:** Cryptographic implementation
   - **Recommendation:**
     - Authenticate the ciphertext before decrypting it.

3. **PCC-006**
   - **Type:** Design decision
   - **Recommendation:**
     - Do not store the hash of the key in the header.
     - Verify the signature before attempting to decrypt the volume.
     - Consider replacing the hash with a MAC of the header.