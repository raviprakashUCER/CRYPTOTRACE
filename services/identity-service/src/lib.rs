pub use identity_core::{
    generate_ml_dsa_keypair, generate_ml_kem_keypair, AuthError, ClearanceLevel,
    CryptographicIdentityPublic, DsaSecretKey, KemSecretKey, KeyStatus, KeyStore, KeyStoreError,
    LocalEncryptedKeyStore, Permission, ProtectedKeystore, Role, User,
};
use std::collections::HashMap;
use storage_sqlite::SqliteDatabase;
use uuid::Uuid;

pub struct IdentityManager {
    pub users: HashMap<String, User>,
    pub db: Option<SqliteDatabase>,
    pub keystore: Option<LocalEncryptedKeyStore>,
}

impl Default for IdentityManager {
    fn default() -> Self {
        Self::new()
    }
}

impl IdentityManager {
    pub fn new() -> Self {
        Self {
            users: HashMap::new(),
            db: None,
            keystore: None,
        }
    }

    pub fn with_database(db: SqliteDatabase, master_passphrase: &str) -> Self {
        let keystore = LocalEncryptedKeyStore::new(master_passphrase);
        let mut mgr = Self {
            users: HashMap::new(),
            db: Some(db.clone()),
            keystore: Some(keystore),
        };

        // Reload existing users from database
        if let Ok(users) = db.list_users() {
            for u in users {
                mgr.users.insert(u.user_id.clone(), u);
            }
        }

        mgr
    }

    /// Registers a new user without cryptographic identity
    pub fn register_user(
        &mut self,
        name: String,
        department: String,
        organization: String,
        clearance_level: ClearanceLevel,
        role: Role,
    ) -> User {
        let user_id = Uuid::new_v4().to_string();
        let user = User {
            user_id: user_id.clone(),
            name,
            department,
            organization,
            clearance_level,
            role,
            cryptographic_identity: None,
            last_authentication: None,
        };

        self.users.insert(user_id.clone(), user.clone());

        if let Some(ref db) = self.db {
            let _ = db.insert_user(&user);
            let _ = db.insert_audit_log(
                "USER_REGISTERED",
                "SYSTEM",
                &user_id,
                &format!("User {} registered with role {}", user.name, user.role),
                "SUCCESS",
            );
        }

        user
    }

    /// Enrolls a user with new PQC keys.
    /// Returns the updated user and the protected keystore.
    pub fn enroll_cryptographic_identity(
        &mut self,
        user_id: &str,
    ) -> Result<(User, ProtectedKeystore), String> {
        let user = self.users.get_mut(user_id).ok_or("User not found")?;

        let (kem_pk, kem_sk) = generate_ml_kem_keypair();
        let (dsa_pk, dsa_sk) = generate_ml_dsa_keypair();

        let identity_id = format!("ID-{}", Uuid::new_v4());
        let public_identity =
            CryptographicIdentityPublic::new(identity_id.clone(), &kem_pk, &dsa_pk);

        user.cryptographic_identity = Some(public_identity.clone());

        let keystore = ProtectedKeystore {
            kem_secret: kem_sk,
            dsa_secret: dsa_sk,
        };

        // Persist to encrypted keystore abstraction if active
        if let Some(ref mut local_ks) = self.keystore {
            local_ks
                .store_key(&identity_id, &keystore)
                .map_err(|e| format!("Keystore save failed: {:?}", e))?;
        }

        // Persist user & public identity to SQLite database if active
        if let Some(ref db) = self.db {
            db.insert_user(user)
                .map_err(|e| format!("Database save failed: {:?}", e))?;
            let _ = db.insert_audit_log(
                "IDENTITY_ENROLLED",
                user_id,
                &identity_id,
                "Enrolled ML-KEM-768 and ML-DSA-65 identity",
                "SUCCESS",
            );
        }

        Ok((user.clone(), keystore))
    }

    // ------------------------------------------------------------------------
    // KEY LIFECYCLE MANAGEMENT (Phase 3)
    // ------------------------------------------------------------------------

    pub fn activate_key(&mut self, identity_id: &str) -> Result<(), String> {
        self.set_key_status(identity_id, KeyStatus::Active, "KEY_ACTIVATED")
    }

    pub fn suspend_key(&mut self, identity_id: &str) -> Result<(), String> {
        self.set_key_status(identity_id, KeyStatus::Suspended, "KEY_SUSPENDED")
    }

    pub fn revoke_key(&mut self, identity_id: &str) -> Result<(), String> {
        self.set_key_status(identity_id, KeyStatus::Revoked, "KEY_REVOKED")
    }

    pub fn expire_key(&mut self, identity_id: &str) -> Result<(), String> {
        self.set_key_status(identity_id, KeyStatus::Expired, "KEY_EXPIRED")
    }

    fn set_key_status(
        &mut self,
        identity_id: &str,
        status: KeyStatus,
        audit_action: &str,
    ) -> Result<(), String> {
        let user = self
            .users
            .values_mut()
            .find(|u| {
                u.cryptographic_identity
                    .as_ref()
                    .map(|i| i.identity_id == identity_id)
                    .unwrap_or(false)
            })
            .ok_or_else(|| format!("Identity not found: {}", identity_id))?;

        if let Some(ref mut ident) = user.cryptographic_identity {
            ident.status = status;
        }

        if let Some(ref db) = self.db {
            db.update_identity_status(identity_id, status)
                .map_err(|e| format!("DB status update failed: {:?}", e))?;
            let _ = db.insert_audit_log(
                audit_action,
                &user.user_id,
                identity_id,
                &format!("Status changed to {}", status),
                "SUCCESS",
            );
        }

        Ok(())
    }

    pub fn get_key_status(&self, identity_id: &str) -> Result<KeyStatus, String> {
        if let Some(ref db) = self.db {
            if let Ok(Some(ident)) = db.get_identity(identity_id) {
                return Ok(ident.status);
            }
        }

        self.users
            .values()
            .find_map(|u| {
                u.cryptographic_identity
                    .as_ref()
                    .filter(|i| i.identity_id == identity_id)
                    .map(|i| i.status)
            })
            .ok_or_else(|| format!("Identity not found: {}", identity_id))
    }

    // ------------------------------------------------------------------------
    // RBAC & CLEARANCE MANAGEMENT (Phase 3)
    // ------------------------------------------------------------------------

    pub fn update_user_role(
        &mut self,
        user_id: &str,
        new_role: Role,
        actor_role: Role,
    ) -> Result<(), AuthError> {
        actor_role.verify_permission(Permission::ManageRoles)?;

        let user = self
            .users
            .get_mut(user_id)
            .ok_or_else(|| AuthError::UnauthorizedRole {
                role: actor_role.to_string(),
                required_permission: "UserNotFound".to_string(),
            })?;

        user.role = new_role;

        if let Some(ref db) = self.db {
            let _ = db.update_user_role(user_id, new_role);
            let _ = db.insert_audit_log(
                "ROLE_UPDATED",
                "ADMIN",
                user_id,
                &format!("Role updated to {}", new_role),
                "SUCCESS",
            );
        }

        Ok(())
    }

    pub fn revoke_identity(&mut self, user_id: &str) -> Result<(), String> {
        let user = self.users.get_mut(user_id).ok_or("User not found")?;
        if let Some(ref mut identity) = user.cryptographic_identity {
            identity.status = KeyStatus::Revoked;
            let identity_id = identity.identity_id.clone();
            if let Some(ref db) = self.db {
                let _ = db.update_identity_status(&identity_id, KeyStatus::Revoked);
            }
        }
        Ok(())
    }

    pub fn get_user_by_identity_id(&self, identity_id: &str) -> Option<&User> {
        self.users.values().find(|u| {
            u.cryptographic_identity
                .as_ref()
                .map(|i| i.identity_id.as_str())
                == Some(identity_id)
        })
    }

    pub fn get_user(&self, user_id: &str) -> Option<&User> {
        self.users.get(user_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqcrypto_traits::kem::SecretKey as _;
    use pqcrypto_traits::sign::SecretKey as _;

    #[test]
    fn test_register_and_enroll_user() {
        let mut manager = IdentityManager::new();
        let user = manager.register_user(
            "Officer Rahul".to_string(),
            "Ministry of Defence".to_string(),
            "Government of India".to_string(),
            ClearanceLevel::TopSecret,
            Role::Recipient,
        );

        assert_eq!(user.name, "Officer Rahul");
        assert!(user.cryptographic_identity.is_none());

        let (enrolled_user, keystore) = manager
            .enroll_cryptographic_identity(&user.user_id)
            .expect("Enrollment failed");

        assert!(enrolled_user.cryptographic_identity.is_some());
        let identity = enrolled_user.cryptographic_identity.unwrap();
        assert_eq!(identity.status, KeyStatus::Active);
        assert!(!identity.kem_public_key.is_empty());
        assert!(!identity.dsa_public_key.is_empty());
        assert!(!keystore.kem_secret.as_bytes().is_empty());
        assert!(!keystore.dsa_secret.as_bytes().is_empty());
    }

    #[test]
    fn test_revoke_identity() {
        let mut manager = IdentityManager::new();
        let user = manager.register_user(
            "Officer Priya".to_string(),
            "Cyber Command".to_string(),
            "Government of India".to_string(),
            ClearanceLevel::Secret,
            Role::Recipient,
        );

        let (enrolled, _) = manager
            .enroll_cryptographic_identity(&user.user_id)
            .unwrap();
        assert_eq!(
            enrolled.cryptographic_identity.unwrap().status,
            KeyStatus::Active
        );

        manager
            .revoke_identity(&user.user_id)
            .expect("Revocation failed");
        let revoked_user = manager.get_user(&user.user_id).unwrap();
        assert_eq!(
            revoked_user.cryptographic_identity.as_ref().unwrap().status,
            KeyStatus::Revoked
        );
    }
}
