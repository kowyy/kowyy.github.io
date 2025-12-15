---
title: Encryption system
date: 2025-12-15
categories: [Criptography]
tags: [python]     # TAG names should always be lowercase
description: Encryption with python. 
---
# Secure Grade Management System

## Overview

This project implements a cryptographically secure academic grade management system that demonstrates real-world security principles.

The system allows professors to assign grades to students, with everything encrypted and digitally signed. Students can then view their grades and verify that the grades are valid and haven't been modified by an external attacker.

### Module Breakdown

- **user_manager.py**: Handles user registration, authentication, and credential management
- **grade_system.py**: Handles grade operations
- **pki_manager.py**: Public Key Infrastructure, certificate generation and validation
- **crypto_manager.py**: Cryptographic primitives (encryption, signing, verification)
- **audit_log.py**: Tamper-evident logging system
- **interactive_test.py**: Command-line interface for manual testing

## The PKI System: Trust Infrastructure

One of the most important parts of this system is the Public Key Infrastructure (PKI). It's modeled after how real certificate authorities work.

### Hierarchical Trust Model

The system uses a two-tier CA hierarchy:

```python
# From pki_manager.py
def setup_pki():
    # Root CA
    root_key = generate_private_key()
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"UC3M"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"UC3M Root CA"),
    ])
    
    root_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        root_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    ).sign(root_key, hashes.SHA256())
```

**Root CA**: It's valid for 10 years (3650 days) and exists purely to sign the Sub CA. In a real deployment, you'd generate this once, use it to sign your subordinate CAs, and then store the private key offline.

**Sub CA**: This intermediate CA is what actually issues user certificates. It's valid for 5 years and has `path_length=0`, meaning it can't create more CAs below it, only end-user certificates.

Why this hierarchy? Security through compartmentalization. If the Sub CA's key gets compromised, you can revoke it with the Root CA and issue a new one. But if your Root CA is offline and secure, your entire PKI doesn't collapse.

### User Certificate

When a user registers, they get a certificate signed by the Sub CA:

```python
def issue_user_certificate(user_public_key, username, role):
    sub_key = load_key_encrypted(SUB_KEY_FILE)
    sub_cert = load_cert(SUB_CERT_FILE)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"UC3M"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, f"Rol: {role}"),
        x509.NameAttribute(NameOID.COMMON_NAME, username),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        sub_cert.subject
    ).public_key(
        user_public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    ).sign(sub_key, hashes.SHA256())
```

Notice how the role is embedded in the `ORGANIZATIONAL_UNIT_NAME` field. This creates role-based certificates where the identity includes both who you are and what you're allowed to do. User certificates are valid for 1 year.

### Certificate Revocation

The system implements a Certificate Revocation List (CRL):

```python
def revoke_certificate(cert_pem):
    cert = x509.load_pem_x509_certificate(cert_pem)
    serial = cert.serial_number
    
    crl = load_crl()
    
    revocation_entry = {
        'serial': serial,
        'revoked_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'reason': 'user_deletion'
    }
    
    crl.append(revocation_entry)
    save_crl(crl)
```

When a user is deleted, their certificate gets added to the CRL. Every login checks this list.

### Certificate Verification

Proper chain verification that validates every link in the trust chain:

```python
def verify_certificate(cert_pem):
    try:
        user_cert = x509.load_pem_x509_certificate(cert_pem)
        sub_cert = load_cert(SUB_CERT_FILE)
        root_cert = load_cert(ROOT_CERT_FILE)
        
        # Check revocation first
        revoked, revoked_at = is_revoked(user_cert)
        if revoked:
            raise Exception(f"Certificate revoked on {revoked_at}")
        
        # Verify User Cert is signed by Sub CA
        sub_cert.public_key().verify(
            user_cert.signature,
            user_cert.tbs_certificate_bytes,
            padding.PKCS1v15(), 
            user_cert.signature_hash_algorithm
        )
        
        # Verify Sub CA is signed by Root CA
        root_cert.public_key().verify(
            sub_cert.signature,
            sub_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            sub_cert.signature_hash_algorithm
        )
        
        # Verify Root CA is self-signed
        root_cert.public_key().verify(
            root_cert.signature,
            root_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            root_cert.signature_hash_algorithm
        )
        
        # Check validity dates for entire chain
        now = datetime.datetime.now(datetime.timezone.utc)
        
        for cert, name in [(user_cert, "User"), (sub_cert, "Sub CA"), (root_cert, "Root CA")]:
            if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
                raise Exception(f"{name} certificate expired or not yet valid")
        
        return True
        
    except Exception as e:
        print(f"Certificate verification failed: {e}")
        return False
```

This ensures proper chain validation. You only explicitly trust the Root CA, and all other trust is derived through cryptographic verification. An attacker can't inject fake certificates at any level.

## User Authentication: Defense in Depth

User authentication combines multiple security layers:

### Password Hashing with Salt

```python
# Registration
salt = os.urandom(16)
digest = hashes.Hash(hashes.SHA256())
digest.update(salt)              
digest.update(password.encode()) 
password_hash = digest.finalize()

# Login verification
digest = hashes.Hash(hashes.SHA256())
digest.update(salt)
digest.update(password.encode())

if digest.finalize() != stored_hash:
    raise ValueError("Contraseña incorrecta.")
```

Each user gets a unique random salt. Even if two users have the same password, their hashes will be completely different. The salt is stored in plaintext, but combined with the password before hashing.

### Key Encryption Issues and Fixes

A proper Key Derivation Function (KDF) is used to derive a strong encryption key from the password.

```python
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# During registration
key_salt = os.urandom(16)  # Separate salt for key derivation
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=key_salt,
    iterations=480000,
)
encryption_key = kdf.derive(password.encode())

# Encrypt with the derived key
private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.BestAvailableEncryption(encryption_key)
)

# Store key_salt along with private_key_pem
db_users[username] = {
    'salt': salt,  # For password verification
    'hash': password_hash,
    'key_salt': key_salt,  # For key decryption
    'private_key_pem': private_key_pem,
    'role': role,
    'certificate_pem': certificate_pem
}

# During login
stored_key_salt = user_data['key_salt']
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=stored_key_salt,
    iterations=480000,
)
encryption_key = kdf.derive(password.encode())

private_key = serialization.load_pem_private_key(
    user_data['private_key_pem'], 
    password=encryption_key
)
```

The KDF applies 480,000 iterations of SHA-256, making brute-force attacks computationally expensive. Even if someone gets the database, they can't easily crack the private keys.

Note that we use **two separate salts**: one for password hashing (authentication) and one for key derivation (encryption). This is defense in depth.

If someone steals the database file, they can't use the private keys without knowing the passwords, and the KDF makes password cracking extremely slow.

## Hybrid Encryption: The Grade Storage System

Grades are protected using **hybrid encryption**, a combination of symmetric and asymmetric crypto.

### Why Hybrid?

RSA (asymmetric encryption) is slow and can only encrypt small amounts of data. AES (symmetric encryption) is fast and can handle large payloads, but requires both parties to share the same key securely. Hybrid encryption gives us the best of both worlds.

### Multi-Recipient Encryption

Here's the grade encryption function:

```python
def encrypt_grade_entry(grade_data_str, student_cert_pem, prof_cert_pem):
    # Extract public keys
    student_pub_key = get_public_key_from_cert(student_cert_pem)
    prof_pub_key = get_public_key_from_cert(prof_cert_pem)
    
    # Generate ephemeral symmetric key (one-time use)
    sym_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(sym_key)
    nonce = os.urandom(12)
    
    # Encrypt the actual grade data with AES
    encrypted_grade = aesgcm.encrypt(nonce, grade_data_str.encode('utf-8'), None)
    
    # Wrap the AES key for the student
    enc_key_student = student_pub_key.encrypt(
        sym_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()), 
            algorithm=hashes.SHA256(), 
            label=None
        )
    )

    # Wrap the same AES key for the professor
    enc_key_prof = prof_pub_key.encrypt(
        sym_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()), 
            algorithm=hashes.SHA256(), 
            label=None
        )
    )
    
    return encrypted_grade, enc_key_student, enc_key_prof, nonce
```

Here's what happens:

1. **Generate a random AES-256 key** - This key exists only for this one grade entry (ephemeral)
2. **Encrypt the grade data with AES-GCM** - Fast, authenticated encryption
3. **Encrypt the AES key with the student's public key** - Now the student can decrypt it
4. **Encrypt the same AES key with the professor's public key** - Now the professor can also decrypt it

The grade data is encrypted **once** with AES, but the key is encrypted **twice** with different public keys. Both recipients can independently decrypt the data, but nobody else can.

### AES-GCM: Why This Mode?

The system uses AES in GCM (Galois/Counter Mode). This is an AEAD (Authenticated Encryption with Associated Data) mode, which provides:

- **Confidentiality**: The data is encrypted
- **Integrity**: Any tampering is detected
- **Authentication**: You know the data hasn't been modified

When you decrypt:

```python
def decrypt_grade_hybrid(encrypted_grade, encrypted_sym_key, nonce, private_key):
    # Unwrap the AES key using RSA private key
    sym_key = private_key.decrypt(
        encrypted_sym_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()), 
            algorithm=hashes.SHA256(), 
            label=None
        )
    )

    # Decrypt the grade using the recovered AES key
    aesgcm = AESGCM(sym_key)
    try:
        decrypted_data_bytes = aesgcm.decrypt(nonce, encrypted_grade, None)
        return decrypted_data_bytes.decode('utf-8')
    except InvalidTag:
        raise ValueError("Error de integridad: los datos parecen haber sido modificados")
```

If someone modifies the encrypted grade, the `InvalidTag` exception is raised. You can't decrypt it and you immediately know something's wrong.

### RSA-OAEP Padding

Notice the OAEP padding scheme:

```python
padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()), 
    algorithm=hashes.SHA256(), 
    label=None
)
```

OAEP (Optimal Asymmetric Encryption Padding) is crucial. Raw RSA encryption is deterministic and vulnerable to certain attacks. OAEP adds randomization and makes the encryption scheme semantically secure. Even if you encrypt the same AES key twice, you'd get different ciphertexts.

## Digital Signatures: Non-Repudiation

Encryption protects confidentiality, but how do we ensure authenticity? Digital signatures.

### Timestamped Signatures

The system uses RSA-PSS signatures with timestamps:

```python
def sign_data_with_timestamp(data_bytes, private_key):
    timestamp = get_timestamp()
    
    # Bind the timestamp to the data
    data_to_sign = data_bytes + timestamp.encode('utf-8')
    
    signature = private_key.sign(
        data_to_sign,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature, timestamp
```

The timestamp is concatenated with the grade data before signing. This prevents replay attacks. You can't take an old signature and claim it's new.

When a professor adds a grade:

```python
grade_data_str = f"Asignatura: {subject} | Calificación: {grade}"

signature, timestamp = crypto_manager.sign_data_with_timestamp(
    grade_data_str.encode('utf-8'), 
    prof_session.private_key
)
```

### RSA-PSS: Probabilistic Signatures

PSS (Probabilistic Signature Scheme) is to signing what OAEP is to encryption. It adds randomization to prevent existential forgery attacks. The signature includes a random salt (different from the password salt), making each signature unique even for identical messages.

### Signature Verification

Students verify signatures when viewing grades:

```python
def view_my_grades(student_session):
    for entry in db_grades[username]:
        (enc_grade, enc_key_student, _, nonce, signature, signer, timestamp) = entry
        
        # Decrypt the grade
        grade_str = crypto_manager.decrypt_grade_hybrid(
            enc_grade, enc_key_student, nonce, student_session.private_key
        )
        
        # Get the professor's public key from their certificate
        signer_cert = user_manager.get_user_certificate(signer)
        signer_pub = crypto_manager.get_public_key_from_cert(signer_cert)
        
        # Verify the signature
        is_valid = crypto_manager.verify_signature_with_timestamp(
            grade_str.encode('utf-8'), signature, timestamp, signer_pub
        )
```

This provides:

- **Authentication**: We know who signed it (the professor)
- **Integrity**: We know the grade hasn't been altered
- **Non-repudiation**: The professor can't deny creating this grade
- **Timestamp validation**: We know when it was created and can detect replays

## Audit System: Tamper Detection

The audit log doesn't just record events, it actively detects tampering.

### Hash-Based Integrity

```python
def log_event(actor, action, target, status="SUCCESS"):
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    entry = (f"[{timestamp}] "
             f"Actor: {actor:20} | "
             f"Action: {action:20} | "
             f"Target: {target} | "
             f"Status: {status}\n")
    
    # Verify nobody touched the file
    verify_audit_integrity()
    
    # Write the new entry
    with open(AUDIT_FILE, "a", encoding='utf-8') as f:
        f.write(entry)
    
    # Save the new hash
    save_audit_hash()
```

Every time an event is logged:

1. Verify the current file hash matches the stored hash
2. Append the new entry
3. Compute and save the new hash

The hash file stores:

```python
{
    'hash': 'sha256_hash_of_entire_log_file',
    'last_update': '2024-12-15T10:30:00+00:00'
}
```

If anyone modifies the log file directly (opening it in a text editor and changing a line), the next operation will detect it:

```python
def verify_audit_integrity():
    with open(AUDIT_HASH_FILE, 'r') as f:
        stored_data = json.load(f)
        stored_hash = stored_data.get('hash')
    
    current_hash = compute_file_hash(AUDIT_FILE)
    
    if current_hash != stored_hash:
        print("\nALERTA DE SEGURIDAD")
        print("El archivo de auditoría ha sido modificado externamente.")
        print(f"Hash esperado: {stored_hash}")
        print(f"Hash actual:   {current_hash}")
        return False
```

### Complete Audit Trail

Every significant action is logged:

```python
# User registration
audit_log.log_event("System", "REGISTER_USER", username, "SUCCESS")

# Login attempts (success and failure)
audit_log.log_event(username, "LOGIN", "System", "FAIL_BAD_PASS")
audit_log.log_event(username, "LOGIN", "System", "SUCCESS")

# Grade operations with full details
change_detail = f"{student_username} | ANTES: [{old_grade_str}] → AHORA: [{new_grade_str}]"
audit_log.log_event(prof_session.username, "MODIFY_GRADE", change_detail, "SUCCESS")
```

This creates a forensic timeline. If something goes wrong, you can trace exactly what happened and who did it.

## Data Persistence: Atomic Writes

All database operations use atomic writes to prevent corruption:

```python
def save_grades_db():
    temp_file = DB_GRADES_FILE + ".tmp"
    
    # ... prepare data ...
    
    try:
        with open(temp_file, 'w') as f:
            json.dump(data_to_save, f, indent=4)
        
        # Atomic rename - either succeeds completely or not at all
        os.replace(temp_file, DB_GRADES_FILE)
        
    except IOError as e:
        print(f"Error al guardar notas: {e}")
        if os.path.exists(temp_file): 
            os.remove(temp_file)
```

The write-to-temp-then-rename pattern ensures you never have a partially written database. If the process crashes during write, the original file is intact. `os.replace()` is atomic on all major platforms.

## Grade Lifecycle Example

Let's walk through a complete grade lifecycle to tie everything together:

### 1. Professor Adds a Grade

```python
grade_system.add_grade(prof_session, "Adam", "Cryptography", "9.5")
```

Internally:
- Validates professor role
- Validates student exists and has valid certificate
- Creates grade string: `"Asignatura: Cryptography | Calificación: 9.5"`
- Signs the data with professor's private key + timestamp
- Generates random AES-256 key
- Encrypts grade with AES-GCM
- Encrypts AES key with student's public key (from certificate)
- Encrypts AES key with professor's public key
- Stores: `(encrypted_grade, enc_key_student, enc_key_prof, nonce, signature, prof_username, timestamp)`
- Saves to database atomically
- Logs event to audit system

### 2. Student Views the Grade

```python
grade_system.view_my_grades(student_session)
```

Internally:
- Retrieves all grade entries for this student
- For each grade:
  - Decrypts AES key using student's private key (RSA-OAEP)
  - Decrypts grade data using recovered AES key (AES-GCM)
  - Retrieves professor's certificate
  - Extracts professor's public key from certificate
  - Verifies signature using professor's public key (RSA-PSS)
  - Validates timestamp is not too old/future
  - Displays: grade data, professor name, timestamp, verification status
- Logs the viewing event

### 3. Professor Modifies the Grade

```python
grade_system.modify_grade(prof_session, "Adam", 0, "Asignatura: Cryptography | Calificación: 10.0")
```

Internally:
- Validates professor owns this grade
- Decrypts old grade for audit log
- Creates new signature with current timestamp
- Re-encrypts with fresh AES key
- Replaces database entry
- Logs: `"MODIFY_GRADE | Adam | ANTES: [9.5] → AHORA: [10.0]"`

The old signature becomes invalid for the new data. You can't modify grades without leaving a trace.

## Improvements That Could Be Made

This is an academic project, so there are areas that could be enhanced for production use:

1. **Database**: Use a proper database system (PostgreSQL, MySQL) instead of JSON files. This would provide ACID guarantees, better concurrency control, and query optimization.

2. **OCSP for revocation**: The CRL is a simple JSON file. Production systems should use OCSP (Online Certificate Status Protocol) for real-time revocation checks, or OCSP stapling for better performance.

3. **Multi-Factor Authentication**: Add TOTP, hardware tokens (FIDO2/WebAuthn), or biometric factors alongside password authentication.

4. **Certificate profiles**: Define proper X.509v3 extensions like Key Usage, Extended Key Usage, and Certificate Policies for more granular control.

5. **Rate limiting**: Add rate limiting for login attempts and other sensitive operations to prevent brute-force attacks.
