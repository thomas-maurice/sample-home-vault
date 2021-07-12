package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/hashicorp/vault/api"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"gopkg.in/yaml.v2"
)

var (
	hosts string
	// KVRoot root of the KV -- to make the linter stfu
	KVRoot     string
	hostBase   string
	approle    string
	sshPath    string
	sshRole    string
	numWorkers int
	debug      bool
)

const (
	approleVarName   = "approle"
	sshKeysVarName   = "ssh"
	sshCertsVarName  = "certs"
	entityVarName    = "entity"
	wgVarName        = "wireguard"
	entityNamePrefix = "host-"
)

var (
	sshKeyTypes = []string{"rsa", "dsa", "ecdsa", "ed25519"}
)

/*
	Something like

	$ cat hosts.yml
	---
	vault: https://vault.example.com
	hostGroupName: hosts
	hostGroupPolicies:
	- foo
	- bar
	hosts:
	r2s:
		wgInterfaces:
		- wg-ospf-a0
	pi4:
		wgInterfaces:
		- wg-ospf-a2
	r1:
		wgInterfaces:
		- wg-ospf-a1
	vpn.example.com:
		wgInterfaces:
		- wg-ospf-a1
		- wg-ospf-a0
*/
type hostList struct {
	Hosts             map[string]ConfiguredHost `yaml:"hosts"`
	Vault             string                    `yaml:"vault"`
	HostGroupName     string                    `yaml:"hostGroupName"`
	HostGroupPolicies []string                  `yaml:"hostGroupPolicies"`
	HostMountAccessor string                    `yaml:"hostMountAccessor"`
}

// ConfiguredHost is a host
type ConfiguredHost struct {
	WGInterfaces []string `yaml:"wgInterfaces"`
}

type vaultData struct {
	Data struct {
		Keys []string `json:"keys"`
	} `json:"data"`
}

// WireguardInterface a wg iface
type WireguardInterface struct {
	Name       string `yaml:"name" json:"json"`
	PublicKey  string `yaml:"public_key" json:"public_key"`
	PrivateKey string `yaml:"private_key" json:"private_key"`
}

// SSHKey is the representation of an SSH key
type SSHKey struct {
	PublicKey   string `yaml:"public_key" json:"public_key"`
	PrivateKey  string `yaml:"private_key" json:"private_key"`
	Type        string `yaml:"type" json:"type"`
	Fingerprint string `yaml:"fingerprint" json:"fingerprint"`
}

// AppRoleInfo is the representation of an approle
type AppRoleInfo struct {
	RoleID      string `yaml:"role_id" json:"role_id"`
	SecretID    string `yaml:"secret_id" json:"secret_id"`
	Path        string `yaml:"path" json:"path"`
	VaultServer string `yaml:"vault_server" json:"vault_server"`
}

// SSHCertificate represents a cert
type SSHCertificate struct {
	Type                 string `json:"type" yaml:"type"`
	Serial               string `json:"serial" yaml:"serial"`
	Certificate          string `json:"certificate" yaml:"certificate"`
	PublicKeyFingerprint string `json:"public_key_fingerprint" yaml:"public_key_fingerprint"`
}

// Host is a host (kv-root, vault client and shit)
type Host struct {
	SSHKeys              map[string]SSHKey         // Type -> Key
	SSHCertificates      map[string]SSHCertificate // Type -> cert
	WireguardInterfaces  map[string]WireguardInterface
	AppRolePath          string
	KVPath               string
	SSHPath              string
	Hostname             string
	AppRoleInfo          AppRoleInfo
	AppRoleMountAccessor string
	vaultClient          *api.Client
	vaultURL             string
	hostBase             string
	wgNames              []string
	hostsGroupName       string
	entityID             string
}

// NewHost creates a new host
func NewHost(
	client *api.Client,
	vaultURL string,
	appRolePath string,
	sshPath string,
	kvPath string,
	hostname string,
	hostBase string,
	wgNames []string,
	hostsGroupName string,
	approleMountAccessor string,
) (*Host, error) {
	ifaces := make(map[string]WireguardInterface)
	return &Host{
		Hostname:    strings.Replace(hostname, ".", "_", -1),
		KVPath:      kvPath,
		AppRolePath: appRolePath,
		vaultClient: client,
		SSHPath:     sshPath,
		vaultURL:    vaultURL,
		hostBase:    hostBase,
		AppRoleInfo: AppRoleInfo{
			Path: appRolePath,
		},
		WireguardInterfaces:  ifaces,
		wgNames:              wgNames,
		hostsGroupName:       hostsGroupName,
		AppRoleMountAccessor: approleMountAccessor,
	}, nil
}

func newSSHKey(hostname string, keyType string) (string, string, error) {
	keyName := uuid.New().String()

	defer os.Remove(keyName)
	defer os.Remove(keyName + ".pub")

	args := []string{
		"-f", path.Join("/tmp", keyName),
		"-t", keyType,
		"-P", "",
		"-q",
		"-C", "generated-" + hostname,
	}

	if keyType == "rsa" {
		args = append(args, "-b", "4096")
	} else if keyType == "ecdsa" {
		args = append(args, "-b", "521")
	}

	c := exec.Command("/usr/bin/ssh-keygen", args...)
	out, err := c.CombinedOutput()
	if err != nil {
		logrus.WithError(err).Errorf("failed running ssh-keygen with args %v: %s", args, string(out))
		return "", "", err
	}

	pub, err := ioutil.ReadFile(path.Join("/tmp", keyName) + ".pub")
	if err != nil {
		return "", "", err
	}

	priv, err := ioutil.ReadFile(path.Join("/tmp", keyName))
	if err != nil {
		return "", "", err
	}

	return string(priv), string(pub), nil
}

// EntityName creates a new entity name for the host
func (h *Host) EntityName() string {
	return fmt.Sprintf("%s%s", entityNamePrefix, h.Hostname)
}

// EntityID returns the ID of the host entity
func (h *Host) EntityID() string {
	return h.entityID
}

// LoadApprole loads the approle info for the host
func (h *Host) LoadApprole() error {
	pth := path.Join(h.KVPath, "data", h.hostBase, h.Hostname, approleVarName)
	d, err := h.vaultClient.Logical().Read(pth)
	if err != nil {
		return err
	}

	if d == nil {
		logrus.Debug("no approle info found")
		return nil
	}

	data, ok := d.Data["data"].(map[string]interface{})
	if !ok {
		return errors.New("could not parse approle data")
	}

	roleID, ok := data["role_id"].(string)
	if !ok {
		return errors.New("could not parse role_id")
	}

	secretID, ok := data["secret_id"].(string)
	if !ok {
		secretID = ""
	}

	h.AppRoleInfo = AppRoleInfo{
		RoleID:   roleID,
		SecretID: secretID,
		Path:     h.AppRolePath,
	}

	return nil
}

// LoadSSH loads all the SSH keys info or the host
func (h *Host) LoadSSH() error {
	if h.SSHKeys == nil {
		h.SSHKeys = make(map[string]SSHKey)
	}

	for _, t := range sshKeyTypes {
		pth := path.Join(h.KVPath, "data", h.hostBase, h.Hostname, sshKeysVarName, t)
		d, err := h.vaultClient.Logical().Read(pth)
		if err != nil {
			return err
		}

		if d == nil {
			logrus.WithFields(h.fields()).Debugf("no ssh key found of type %s", t)
			continue
		}

		data, ok := d.Data["data"].(map[string]interface{})
		if !ok {
			return errors.New("could not parse ssh data")
		}

		private, ok := data["private"].(string)
		if !ok {
			return errors.New("could not parse private key")
		}

		if t != "ecdsa" && t != "dsa" {
			// ecdsa and dsa keys are unhandled for some reason
			_, err = ssh.ParsePrivateKey([]byte(private))
			if err != nil {
				logrus.WithError(err).WithFields(h.fields()).Errorf("could not parse stored %s key, discarding it", t)
				continue
			}
		}
		public, ok := data["public"].(string)
		if !ok {
			return errors.New("could not parse public key")
		}

		pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(public))
		if err != nil {
			return err
		}
		fingerprint := ssh.FingerprintSHA256(pk)

		h.SSHKeys[t] = SSHKey{
			PublicKey:   public,
			PrivateKey:  private,
			Type:        t,
			Fingerprint: fingerprint,
		}
	}

	return nil
}

// LoadEntity loads the entity from the KV store
func (h *Host) LoadEntity() error {
	pth := path.Join("identity", "entity", "name", h.EntityName())
	d, err := h.vaultClient.Logical().Read(pth)
	if err != nil {
		return err
	}

	if d == nil {
		logrus.Debug("no entity info found")
		return nil
	}

	id, ok := d.Data["id"].(string)
	if !ok {
		return errors.New("could not parse entity id")
	}

	h.entityID = id

	return nil
}

// SaveEntityIDInKV saves the entity names and ID in the KV store
func (h *Host) SaveEntityIDInKV() error {
	pth := path.Join(h.KVPath, "data", h.hostBase, h.Hostname, entityVarName)
	_, err := h.vaultClient.Logical().Write(
		pth,
		map[string]interface{}{
			"data": map[string]interface{}{
				"name": h.EntityName(),
				"id":   h.entityID,
			},
		},
	)

	if err != nil {
		return err
	}

	return nil
}

// SaveEntity saves the newly created entity to vault
func (h *Host) SaveEntity() error {
	pth := path.Join("identity", "entity", "name", h.EntityName())
	d, err := h.vaultClient.Logical().Write(
		pth,
		map[string]interface{}{
			"name": h.EntityName(),
			"metadata": map[string]string{
				"type":     "host",
				"hostname": h.Hostname,
			},
		},
	)

	if err != nil {
		return err
	}

	if d == nil {
		return nil
	}

	id, ok := d.Data["id"].(string)
	if !ok {
		return errors.New("could not parse entity id -- post create")
	}

	h.entityID = id

	return h.SaveEntityIDInKV()
}

// SaveEntityAlias saves the mapping between the approle and the entity in vault
func (h *Host) SaveEntityAlias() error {
	pth := path.Join("identity", "entity-alias")
	_, err := h.vaultClient.Logical().Write(
		pth,
		map[string]interface{}{
			"name":           h.AppRoleInfo.RoleID,
			"mount_accessor": h.AppRoleMountAccessor,
			"canonical_id":   h.entityID,
		},
	)

	if err != nil {
		return err
	}

	return nil
}

// SaveAppRole saves the approle to vault in the secret backend
func (h *Host) SaveAppRole() error {
	pth := path.Join(h.KVPath, "data", h.hostBase, h.Hostname, approleVarName)
	_, err := h.vaultClient.Logical().Write(
		pth,
		map[string]interface{}{
			"data": map[string]interface{}{
				"role_id":      h.AppRoleInfo.RoleID,
				"secret_id":    h.AppRoleInfo.SecretID,
				"path":         h.AppRolePath,
				"vault_server": h.vaultURL,
			},
		},
	)

	if err != nil {
		return err
	}

	return nil
}

// FillInMissingWireguard generates missing wg keys
func (h *Host) FillInMissingWireguard() error {
	for _, name := range h.wgNames {
		iface, ok := h.WireguardInterfaces[name]
		if !ok || iface.PrivateKey == "" {
			key, err := wgtypes.GeneratePrivateKey()
			if err != nil {
				return err
			}

			logrus.WithFields(h.fields()).Infof("generating wireguard key for interface %s", name)
			h.WireguardInterfaces[name] = WireguardInterface{
				PublicKey:  key.PublicKey().String(),
				PrivateKey: key.String(),
			}
		}
	}

	return nil
}

// SaveWireguard saves the generated keys
func (h *Host) SaveWireguard() error {
	for name, iface := range h.WireguardInterfaces {
		pth := path.Join(h.KVPath, "data", h.hostBase, h.Hostname, wgVarName, name)
		logrus.WithFields(h.fields()).Infof("saving wireguard secrets in %s", pth)
		_, err := h.vaultClient.Logical().Write(
			pth,
			map[string]interface{}{
				"data": map[string]interface{}{
					"private_key": iface.PrivateKey,
					"public_key":  iface.PublicKey,
				},
			},
		)
		if err != nil {
			return err
		}
	}
	return nil
}

// FillInMissingAppRole fills in the app role if it does not exist
func (h *Host) FillInMissingAppRole() error {
	var roleID, secretID string
	pth := path.Join(h.AppRolePath, "role", h.Hostname, "role-id")
	d, err := h.vaultClient.Logical().Read(pth)

	if err != nil {
		return err
	}

	if d == nil {
		logrus.WithFields(h.fields()).Info("creating approle")
		_, err = h.vaultClient.Logical().Write(path.Join(h.AppRolePath, "role", h.Hostname), nil)
		if err != nil {
			panic(err)
		}

		pth := path.Join(h.AppRolePath, "role", h.Hostname, "role-id")
		d, err = h.vaultClient.Logical().Read(pth)

		if err != nil {
			return err
		}
		roleID = d.Data["role_id"].(string)

		d, err = h.vaultClient.Logical().Write(path.Join(h.AppRolePath, "role", h.Hostname, "secret-id"), nil)
		if err != nil {
			return err
		}

		secretID = d.Data["secret_id"].(string)
		h.AppRoleInfo = AppRoleInfo{
			RoleID:   roleID,
			SecretID: secretID,
			Path:     h.AppRolePath,
		}
	} else {
		h.AppRoleInfo.RoleID = d.Data["role_id"].(string)
		logrus.WithFields(h.fields()).Debug("approle already exists")
		if h.AppRoleInfo.SecretID == "" {
			logrus.WithFields(h.fields()).Info("no secretID registered, generating one")
			d, err = h.vaultClient.Logical().Write(path.Join(h.AppRolePath, "role", h.Hostname, "secret-id"), nil)
			if err != nil {
				return err
			}

			secretID = d.Data["secret_id"].(string)
			h.AppRoleInfo.SecretID = secretID
		}
	}

	return nil
}

// Load loads the host data from Vault
func (h *Host) Load() error {
	err := h.LoadApprole()
	if err != nil {
		return err
	}
	err = h.LoadSSH()
	if err != nil {
		return err
	}
	err = h.LoadWireguard()
	if err != nil {
		return err
	}

	err = h.LoadEntity()
	if err != nil {
		return err
	}

	return nil
}

// Clean cleans up tings that shoud not be there
func (h *Host) Clean() error {
	err := h.CleanupWireguard()
	if err != nil {
		return err
	}
	return nil
}

// LoadWireguard loads all the Wireguard interfaces
func (h *Host) LoadWireguard() error {
	basePath := path.Join(h.KVPath, "metadata", h.hostBase, h.Hostname, wgVarName)
	d, err := h.vaultClient.Logical().List(basePath)
	if err != nil {
		return err
	}

	b, err := json.Marshal(d)
	if err != nil {
		return err
	}

	var interfacesNames vaultData
	err = json.Unmarshal(b, &interfacesNames)
	if err != nil {
		return err
	}

	for _, k := range interfacesNames.Data.Keys {
		pth := path.Join(h.KVPath, "data", h.hostBase, h.Hostname, wgVarName, k)
		d, err := h.vaultClient.Logical().Read(pth)
		if err != nil {
			return err
		}

		if d == nil {
			logrus.WithFields(h.fields()).Debug("no wireguard secret found")
			return nil
		}

		data, ok := d.Data["data"].(map[string]interface{})
		if !ok {
			return errors.New("could not parse data")
		}

		publicKey, ok := data["public_key"].(string)
		if !ok {
			return errors.New("could not parse public key data")
		}

		privateKey, ok := data["private_key"].(string)
		if !ok {
			return errors.New("could not parse private key data")
		}

		h.WireguardInterfaces[k] = WireguardInterface{
			PublicKey:  publicKey,
			PrivateKey: privateKey,
		}
	}

	return nil
}

// CleanupWireguard cleans up unused keys
func (h *Host) CleanupWireguard() error {
	pth := path.Join(KVRoot, "metadata", h.hostBase, h.Hostname, wgVarName)

	registeredInterfaces := make(map[string]bool)
	for _, name := range h.wgNames {
		registeredInterfaces[name] = true
	}

	d, err := h.vaultClient.Logical().List(pth)
	if err != nil {
		return err
	}

	b, err := json.Marshal(d)
	if err != nil {
		return err
	}

	var ifaces vaultData
	err = json.Unmarshal(b, &ifaces)
	if err != nil {
		return err
	}

	for _, name := range ifaces.Data.Keys {
		logrus.WithFields(h.fields()).Infof("checking if interface wireguard secret %s should exist", name)

		_, ok := registeredInterfaces[name]
		if !ok {
			logrus.WithFields(h.fields()).Infof("deleting secrets for wireguard interface %s/%s", h.Hostname, name)
			err = recurseRemove(h.vaultClient, KVRoot, h.hostBase, path.Join(h.Hostname, wgVarName, name))
			if err != nil {
				logrus.WithError(err).Fatalf("could not remove path %s", path.Join(h.Hostname, wgVarName, name))
			}
		} else {
			logrus.WithFields(h.fields()).Debugf("secrets for %s@%s are ok", h.Hostname, path.Join(h.Hostname, wgVarName, name))
		}
	}

	return nil
}

// gets host fields for logging
func (h *Host) fields() logrus.Fields {
	return logrus.Fields{
		"hostname":  h.Hostname,
		"role_id":   h.AppRoleInfo.RoleID,
		"role_path": h.AppRolePath,
	}
}

// FillInMissingSSH generates ssh keys
func (h *Host) FillInMissingSSH() error {
	if h.SSHKeys == nil {
		h.SSHKeys = make(map[string]SSHKey)
	}

	if _, ok := h.SSHKeys["ecdsa"]; !ok {
		logrus.WithFields(h.fields()).Info("generating ecdsa key")

		priv, pub, err := newSSHKey(h.Hostname, "ecdsa")
		if err != nil {
			return err
		}

		pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pub))
		if err != nil {
			return err
		}
		fingerprint := ssh.FingerprintSHA256(pk)

		k := SSHKey{
			PublicKey:   pub,
			PrivateKey:  priv,
			Type:        "ecdsa",
			Fingerprint: fingerprint,
		}

		h.SSHKeys["ecdsa"] = k
	} else {
		logrus.WithFields(h.fields()).Debug("key type ecdsa is present")
	}

	if _, ok := h.SSHKeys["ed25519"]; !ok {
		logrus.WithFields(h.fields()).Info("generating ed25519 key")

		priv, pub, err := newSSHKey(h.Hostname, "ed25519")
		if err != nil {
			return err
		}

		pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pub))
		if err != nil {
			return err
		}
		fingerprint := ssh.FingerprintSHA256(pk)

		k := SSHKey{
			PublicKey:   pub,
			PrivateKey:  priv,
			Type:        "ed25519",
			Fingerprint: fingerprint,
		}

		h.SSHKeys["ed25519"] = k
	} else {
		logrus.WithFields(h.fields()).Debug("key type ed25519 is present")
	}

	if _, ok := h.SSHKeys["rsa"]; !ok {
		logrus.WithFields(h.fields()).Info("generating rsa key")

		priv, pub, err := newSSHKey(h.Hostname, "rsa")
		if err != nil {
			return err
		}

		pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pub))
		if err != nil {
			return err
		}
		fingerprint := ssh.FingerprintSHA256(pk)

		k := SSHKey{
			PublicKey:   pub,
			PrivateKey:  priv,
			Type:        "rsa",
			Fingerprint: fingerprint,
		}

		h.SSHKeys["rsa"] = k
	} else {
		logrus.WithFields(h.fields()).Debug("key type rsa is present")
	}

	if _, ok := h.SSHKeys["dsa"]; !ok {
		logrus.WithFields(h.fields()).Info("generating dsa key")

		priv, pub, err := newSSHKey(h.Hostname, "dsa")
		if err != nil {
			return err
		}

		pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pub))
		if err != nil {
			return err
		}
		fingerprint := ssh.FingerprintSHA256(pk)

		k := SSHKey{
			PublicKey:   pub,
			PrivateKey:  priv,
			Type:        "dsa",
			Fingerprint: fingerprint,
		}

		h.SSHKeys["dsa"] = k
	} else {
		logrus.WithFields(h.fields()).Debug("key type dsa is present")
	}

	return nil
}

// FillInMissingSSHCert generates SSH certificates and renews them if needed
func (h *Host) FillInMissingSSHCert() error {
	if h.SSHCertificates == nil {
		h.SSHCertificates = make(map[string]SSHCertificate)
	}

	for _, t := range sshKeyTypes {
		pth := path.Join(h.KVPath, "data", h.hostBase, h.Hostname, sshCertsVarName, t)
		d, err := h.vaultClient.Logical().Read(pth)
		if err != nil {
			return err
		}

		generate := false
		if d == nil {
			generate = true
		} else {
			data, ok := d.Data["data"].(map[string]interface{})
			if !ok {
				logrus.WithError(err).WithFields(h.fields()).Errorf("could not parse ssh certificate data from secret %s", t)
				generate = true
				goto CertificateGeneration
			}

			certificate, ok := data["certificate"].(string)
			if !ok {
				logrus.WithError(err).WithFields(h.fields()).Errorf("could not retrieve stored certificate %s", t)
				generate = true
				goto CertificateGeneration

			}

			cert, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certificate))
			if err != nil {
				logrus.WithError(err).WithFields(h.fields()).Errorf("could not parse stored certificate %s", t)
				generate = true
				goto CertificateGeneration
			}
			parsedCert := cert.(*ssh.Certificate)
			if int64(parsedCert.ValidBefore)-time.Now().Unix() < (3600*24*365)/2 { // 6 months
				logrus.WithFields(h.fields()).WithField("key_type", t).Info("the ssh certificate expires in less than six months, renewing it")
				generate = true
			} else {
				logrus.WithFields(h.fields()).WithField("key_type", t).Debug("the ssh certificate expires in more than six months, not renewing it")
				h.SSHCertificates[t] = SSHCertificate{
					Type:                 t,
					Serial:               data["serial"].(string),
					Certificate:          data["certificate"].(string),
					PublicKeyFingerprint: ssh.FingerprintSHA256(parsedCert.Key),
				}
			}
		}

	CertificateGeneration:
		if generate {
			logrus.WithFields(h.fields()).WithField("key_type", t).Debugf("generating ssh certificate")
			sigPath := path.Join(h.SSHPath, "sign", sshRole)
			d, err := h.vaultClient.Logical().Write(
				sigPath,
				map[string]interface{}{
					"cert_type":  "host",
					"public_key": h.SSHKeys[t].PublicKey,
				},
			)

			if err != nil {
				return err
			}

			data := d.Data
			serial, ok := data["serial_number"].(string)
			if !ok {
				return errors.New("could not get ssh certificate serial number")
			}

			cert, ok := data["signed_key"].(string)
			if !ok {
				return errors.New("could not get ssh certificate signed key")
			}

			certificate, _, _, _, err := ssh.ParseAuthorizedKey([]byte(cert))
			if err != nil {
				logrus.WithError(err).WithFields(h.fields()).WithField("key_type", t).Errorf("could not parse generated certificate")
				generate = true
				goto CertificateGeneration
			}
			parsedCert := certificate.(*ssh.Certificate)

			h.SSHCertificates[t] = SSHCertificate{
				Type:                 t,
				Serial:               serial,
				Certificate:          cert,
				PublicKeyFingerprint: ssh.FingerprintSHA256(parsedCert.Key),
			}
		}
	}

	return nil
}

// FillInMissing fills in all missing configurations for the hosts
func (h *Host) FillInMissing() error {
	err := h.FillInMissingSSH()
	if err != nil {
		return err
	}
	err = h.FillInMissingSSHCert()
	if err != nil {
		return err
	}
	err = h.FillInMissingAppRole()
	if err != nil {
		return err
	}
	err = h.FillInMissingWireguard()
	if err != nil {
		return err
	}
	return nil
}

// Save saves the changes on a host and performs some cleanup
func (h *Host) Save() error {
	for _, t := range sshKeyTypes {
		pth := path.Join(KVRoot, "data", h.hostBase, h.Hostname, sshKeysVarName, t)
		_, err := h.vaultClient.Logical().Write(
			pth,
			map[string]interface{}{
				"data": map[string]interface{}{
					"private":     h.SSHKeys[t].PrivateKey,
					"public":      h.SSHKeys[t].PublicKey,
					"type":        h.SSHKeys[t].Type,
					"fingerprint": h.SSHKeys[t].Fingerprint,
				},
			},
		)

		if err != nil {
			return err
		}
	}

	for _, t := range sshKeyTypes {
		pth := path.Join(KVRoot, "data", h.hostBase, h.Hostname, sshCertsVarName, t)
		_, err := h.vaultClient.Logical().Write(
			pth,
			map[string]interface{}{
				"data": map[string]interface{}{
					"certificate":            h.SSHCertificates[t].Certificate,
					"serial":                 h.SSHCertificates[t].Serial,
					"type":                   h.SSHCertificates[t].Type,
					"public_key_fingerprint": h.SSHCertificates[t].PublicKeyFingerprint,
				},
			},
		)
		if err != nil {
			return err
		}
	}

	err := h.SaveAppRole()
	if err != nil {
		return err
	}

	err = h.SaveWireguard()
	if err != nil {
		return err
	}

	err = h.SaveEntity()
	if err != nil {
		return err
	}

	err = h.SaveEntityAlias()
	if err != nil {
		return err
	}

	return nil
}

// cleans up approles that should not be here
func cleanupApproles(vaultClient *api.Client, hl hostList) error {
	registeredHost := make(map[string]bool)
	for hst := range hl.Hosts {
		hostname := strings.Replace(hst, ".", "_", -1)
		registeredHost[hostname] = true
	}

	d, err := vaultClient.Logical().List(path.Join(approle, "role"))
	if err != nil {
		return err
	}

	b, err := json.Marshal(d)
	if err != nil {
		return err
	}

	var roleNames vaultData
	err = json.Unmarshal(b, &roleNames)
	if err != nil {
		return err
	}

	for _, hostname := range roleNames.Data.Keys {
		logrus.Infof("checking if %s should exist", hostname)

		_, ok := registeredHost[hostname]
		if !ok {
			logrus.Infof("deleting approle for %s", hostname)
			_, err = vaultClient.Logical().Delete(path.Join(approle, "role", hostname))
			if err != nil {
				return err
			}
		} else {
			logrus.Debugf("approle for host %s is ok", hostname)
		}
	}

	return nil
}

// cleans up approles that should not be here
func cleanupEntities(vaultClient *api.Client, hl []*Host) error {
	registeredHost := make(map[string]bool)
	for _, hst := range hl {
		registeredHost[hst.EntityName()] = true
	}

	d, err := vaultClient.Logical().List(path.Join("identity/entity/name"))
	if err != nil {
		return err
	}

	b, err := json.Marshal(d)
	if err != nil {
		return err
	}

	var entities vaultData
	err = json.Unmarshal(b, &entities)
	if err != nil {
		return err
	}

	for _, entityName := range entities.Data.Keys {
		if !strings.HasPrefix(entityName, entityNamePrefix) {
			continue
		}
		logrus.Infof("checking if entity %s should exist", entityName)

		_, ok := registeredHost[entityName]
		if !ok {
			logrus.Infof("deleting entity for %s", entityName)
			_, err = vaultClient.Logical().Delete(path.Join("identity/entity/name", entityName))
			if err != nil {
				return err
			}
		} else {
			logrus.Debugf("entity for host %s is ok", entityName)
		}
	}

	return nil
}

// helper func to recursively rm -r
func recurseRemove(vaultClient *api.Client, base string, hostBase string, pth string) error {
	d, err := vaultClient.Logical().List(path.Join(base, "metadata", hostBase, pth))
	if err != nil {
		return err
	}

	b, err := json.Marshal(d)
	if err != nil {
		logrus.Fatal(err)
		return err
	}

	var roleNames vaultData
	err = json.Unmarshal(b, &roleNames)
	if err != nil {
		return err
	}

	for _, k := range roleNames.Data.Keys {
		err = recurseRemove(vaultClient, base, hostBase, path.Join(pth, k))
		if err != nil {
			return err
		}
	}

	if len(roleNames.Data.Keys) == 0 {
		_, err = vaultClient.Logical().Delete(path.Join(base, "metadata", hostBase, pth))
		if err != nil {
			logrus.WithError(err).Errorf("could not delete %s", pth)
		} else {
			logrus.Infof("deleting secret at path %s", path.Join(base, hostBase, pth))
			_, err = vaultClient.Logical().Delete(path.Join(base, "metadata", hostBase, pth))
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// removes useless hosts
func cleanupSecrets(vaultClient *api.Client, hostBase string, hl hostList) error {
	pth := path.Join(KVRoot, "metadata", hostBase)

	registeredHost := make(map[string]bool)
	for hst := range hl.Hosts {
		hostname := strings.Replace(hst, ".", "_", -1)
		registeredHost[hostname] = true
	}

	d, err := vaultClient.Logical().List(pth)
	if err != nil {
		return err
	}

	b, err := json.Marshal(d)
	if err != nil {
		return err
	}

	var roleNames vaultData
	err = json.Unmarshal(b, &roleNames)
	if err != nil {
		return err
	}

	for _, hostname := range roleNames.Data.Keys {
		hostname = strings.Replace(hostname, "/", "", -1)
		logrus.Infof("checking if secret %s should exist", hostname)

		_, ok := registeredHost[hostname]
		if !ok {
			logrus.Infof("deleting secrets for %s", hostname)
			err = recurseRemove(vaultClient, KVRoot, hostBase, hostname)
			if err != nil {
				return err
			}
		} else {
			logrus.Debugf("secrets for %s are ok", hostname)
		}
	}

	return nil
}

func updateHostGroup(vaultClient *api.Client, cfg hostList, hl []*Host) error {
	entities := make([]string, 0)
	for _, h := range hl {
		if h.EntityID() == "" {
			return fmt.Errorf("could not find an entity id for %s", h.Hostname)
		}

		entities = append(entities, h.EntityID())
	}

	pth := path.Join("identity/group/name", cfg.HostGroupName)
	_, err := vaultClient.Logical().Write(
		pth,
		map[string]interface{}{
			"name":              cfg.HostGroupName,
			"member_entity_ids": entities,
			"metadata": map[string]string{
				"type": "host",
			},
			"policies": cfg.HostGroupPolicies,
		},
	)

	if err != nil {
		return err
	}

	return nil
}

func init() {
	flag.BoolVar(&debug, "debug", false, "debug or not ?")
	flag.StringVar(&hosts, "hosts", "hosts.yml", "hosts files")
	flag.StringVar(&KVRoot, "kv-root", "hosts/kv/", "KVRoot files")
	flag.StringVar(&hostBase, "host-base", "hosts", "hosts base files")
	flag.StringVar(&approle, "approle", "auth/hosts/app", "approle")
	flag.StringVar(&sshPath, "ssh-path", "prod/ssh", "ssh path")
	flag.StringVar(&sshRole, "ssh-role", "host", "ssh role")
	flag.IntVar(&numWorkers, "workers", 10, "How many concurrent workers do we want")
}

func main() {
	flag.Parse()
	logrus.Infof("configuration file : %s", hosts)
	if debug {
		logrus.SetLevel(logrus.DebugLevel)
	}
	logrus.Infof("running with %d workers", numWorkers)

	vaultConfig := api.DefaultConfig()
	vaultClient, err := api.NewClient(vaultConfig)

	if err != nil {
		panic(err)
	}

	b, err := ioutil.ReadFile(hosts)
	if err != nil {
		panic(err)
	}

	var hl hostList
	err = yaml.Unmarshal(b, &hl)
	if err != nil {
		panic(err)
	}

	vaultHostList := make([]*Host, 0)

	hostChannel := make(chan *Host, numWorkers)
	wg := sync.WaitGroup{}
	wg.Add(len(hl.Hosts))
	mtx := sync.Mutex{}

	for i := 0; i < numWorkers; i++ {
		workerID := i
		go func() {
			for h := range hostChannel {
				logrus.WithFields(h.fields()).WithField("worker_id", workerID).Info("processing host")
				err = h.Load()
				if err != nil {
					logrus.WithError(err).Fatal("could not load")
				}

				err = h.FillInMissing()
				if err != nil {
					logrus.WithError(err).Fatal("could not fill in missing")
				}

				err = h.Save()
				if err != nil {
					logrus.WithError(err).Fatal("could not save")
				}

				err = h.Clean()
				if err != nil {
					logrus.WithError(err).Fatal("could not perform clean")
				}
				mtx.Lock()
				vaultHostList = append(vaultHostList, h)
				mtx.Unlock()

				wg.Done()
			}
		}()
	}

	for hostname, host := range hl.Hosts {
		h, err := NewHost(
			vaultClient,
			hl.Vault,
			approle,
			sshPath,
			KVRoot,
			hostname,
			hostBase,
			host.WGInterfaces,
			hl.HostGroupName,
			hl.HostMountAccessor,
		)
		if err != nil {
			panic(err)
		}
		hostChannel <- h
	}

	logrus.Info("waiting for all the hosts to be processed")
	wg.Wait()
	logrus.Info("all hosts processed")

	logrus.Info("proceeding to cleaning up approles")
	err = cleanupApproles(vaultClient, hl)
	if err != nil {
		logrus.WithError(err).Error("could not cleanup approles")
	}
	logrus.Info("proceeding to cleaning up secrets")
	err = cleanupSecrets(vaultClient, hostBase, hl)
	if err != nil {
		logrus.WithError(err).Error("could not cleanup secrets")
	}
	logrus.Info("proceeding to cleaning up entities")
	err = cleanupEntities(vaultClient, vaultHostList)
	if err != nil {
		logrus.WithError(err).Error("could not cleanup entities")
	}

	logrus.Infof("proceeding to update the group memberships (%s)", hl.HostGroupName)
	err = updateHostGroup(vaultClient, hl, vaultHostList)
	if err != nil {
		logrus.WithError(err).Error("could not update the group")
	}
}
