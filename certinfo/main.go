package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/ddulesov/gogost/gost34112012256"
)

func main() {
	var asJSON bool
	flag.BoolVar(&asJSON, "json", false, "вывести JSON вместо текста")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Использование: certinfo [-json] <файл.cer|.pem|.der | ->\n")
		fmt.Fprintf(os.Stderr, "  разбор ГОСТ-сертификата: Subject/Issuer, срок, алгоритм, отпечатки, extensions\n")
		fmt.Fprintf(os.Stderr, "  вход: PEM или DER; \"-\" — читать со stdin\n")
	}
	flag.Parse()
	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(2)
	}

	if err := run(flag.Arg(0), asJSON); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
}

func run(path string, asJSON bool) error {
	raw, err := readInput(path)
	if err != nil {
		return err
	}
	der, err := toDER(raw)
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("разбор сертификата: %w", err)
	}

	rep := buildReport(cert)

	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		return enc.Encode(rep)
	}
	fmt.Print(renderText(rep))
	return nil
}

func readInput(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("чтение %s: %w", path, err)
	}
	return b, nil
}

// toDER принимает PEM (берёт первый блок CERTIFICATE) или сырой DER.
func toDER(raw []byte) ([]byte, error) {
	if !strings.Contains(string(raw), "-----BEGIN") {
		return raw, nil
	}
	rest := raw
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			return block.Bytes, nil
		}
	}
	return nil, fmt.Errorf("в PEM не найден блок CERTIFICATE")
}

// --- модель отчёта ---

type nameEntry struct {
	Label string `json:"label"`
	OID   string `json:"oid"`
	Value string `json:"value"`
}

type extEntry struct {
	OID      string `json:"oid"`
	Name     string `json:"name,omitempty"`
	Critical bool   `json:"critical"`
}

type report struct {
	Subject []nameEntry `json:"subject"`
	Issuer  []nameEntry `json:"issuer"`

	SerialHex string `json:"serial_hex"`
	SerialDec string `json:"serial_dec"`
	Version   int    `json:"version"`

	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
	Status    string `json:"status"`
	DaysLeft  int    `json:"days_left"`

	PublicKeyOID  string `json:"public_key_oid"`
	PublicKeyName string `json:"public_key_name"`
	PublicKeyBits int    `json:"public_key_bits,omitempty"`
	SignatureOID  string `json:"signature_oid"`
	SignatureName string `json:"signature_name"`

	FpSHA1      string `json:"fingerprint_sha1"`
	FpSHA256    string `json:"fingerprint_sha256"`
	FpStreebog  string `json:"fingerprint_streebog256"`

	KeyUsage         []string   `json:"key_usage,omitempty"`
	ExtKeyUsage      []string   `json:"ext_key_usage,omitempty"`
	BasicConstraints string     `json:"basic_constraints,omitempty"`
	SubjectKeyID     string     `json:"subject_key_id,omitempty"`
	AuthorityKeyID   string     `json:"authority_key_id,omitempty"`
	CRLPoints        []string   `json:"crl_distribution_points,omitempty"`
	OCSP             []string   `json:"ocsp,omitempty"`
	CAIssuers        []string   `json:"ca_issuers,omitempty"`
	Policies         []string   `json:"policies,omitempty"`
	SubjectSignTool  string     `json:"subject_sign_tool,omitempty"`
	IssuerSignTool   string     `json:"issuer_sign_tool,omitempty"`
	OtherExtensions  []extEntry `json:"other_extensions,omitempty"`
}

// --- сборка отчёта ---

func buildReport(cert *x509.Certificate) *report {
	r := &report{}

	r.Subject = names(cert.Subject.Names)
	r.Issuer = names(cert.Issuer.Names)

	r.SerialHex = strings.ToUpper(fmt.Sprintf("%X", cert.SerialNumber.Bytes()))
	r.SerialDec = cert.SerialNumber.String()
	r.Version = cert.Version

	r.NotBefore = cert.NotBefore.UTC().Format(time.RFC3339)
	r.NotAfter = cert.NotAfter.UTC().Format(time.RFC3339)
	now := time.Now()
	switch {
	case now.Before(cert.NotBefore):
		r.Status = "ещё не вступил в силу"
	case now.After(cert.NotAfter):
		r.Status = "истёк"
	default:
		r.Status = "действует"
	}
	r.DaysLeft = int(cert.NotAfter.Sub(now).Hours() / 24)

	// Алгоритмы
	if oid := pubKeyOID(cert); oid != "" {
		r.PublicKeyOID = oid
		if a, ok := pubKeyAlgs[oid]; ok {
			r.PublicKeyName = a.Name
			r.PublicKeyBits = a.Bits
		}
	}
	if oid := sigOID(cert); oid != "" {
		r.SignatureOID = oid
		r.SignatureName = sigAlgs[oid]
	}

	r.FpSHA1 = hexColons(sha1Sum(cert.Raw))
	r.FpSHA256 = hexColons(sha256Sum(cert.Raw))
	r.FpStreebog = hexColons(streebog256(cert.Raw))

	r.KeyUsage = keyUsage(cert.KeyUsage)
	r.ExtKeyUsage = extKeyUsage(cert)
	if cert.BasicConstraintsValid {
		if cert.IsCA {
			r.BasicConstraints = "CA: да"
			if cert.MaxPathLenZero || cert.MaxPathLen > 0 {
				r.BasicConstraints += fmt.Sprintf(", макс. длина пути: %d", cert.MaxPathLen)
			}
		} else {
			r.BasicConstraints = "CA: нет (конечный сертификат)"
		}
	}
	if len(cert.SubjectKeyId) > 0 {
		r.SubjectKeyID = hexColons(cert.SubjectKeyId)
	}
	if len(cert.AuthorityKeyId) > 0 {
		r.AuthorityKeyID = hexColons(cert.AuthorityKeyId)
	}
	r.CRLPoints = cert.CRLDistributionPoints
	r.OCSP = cert.OCSPServer
	r.CAIssuers = cert.IssuingCertificateURL
	r.Policies = policies(cert.PolicyIdentifiers)

	r.SubjectSignTool = signToolString(cert, "1.2.643.100.111")
	r.IssuerSignTool = signToolString(cert, "1.2.643.100.112")

	r.OtherExtensions = otherExtensions(cert)
	return r
}

func names(attrs []pkix.AttributeTypeAndValue) []nameEntry {
	out := make([]nameEntry, 0, len(attrs))
	for _, a := range attrs {
		oid := a.Type.String()
		label := dnNames[oid]
		if label == "" {
			label = oid
		}
		out = append(out, nameEntry{Label: label, OID: oid, Value: attrValue(a.Value)})
	}
	return out
}

func attrValue(v any) string {
	switch s := v.(type) {
	case string:
		return s
	case []byte:
		return string(s)
	default:
		return fmt.Sprintf("%v", v)
	}
}

// pubKeyOID достаёт OID алгоритма открытого ключа из RawSubjectPublicKeyInfo.
func pubKeyOID(cert *x509.Certificate) string {
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &spki); err != nil {
		return ""
	}
	return spki.Algorithm.Algorithm.String()
}

// sigOID достаёт OID алгоритма подписи из головы TBSCertificate. Лишние поля
// SEQUENCE encoding/asn1 при разборе в структуру просто игнорирует.
func sigOID(cert *x509.Certificate) string {
	var tbs struct {
		Version   int `asn1:"optional,explicit,default:0,tag:0"`
		Serial    *big.Int
		Signature pkix.AlgorithmIdentifier
	}
	if _, err := asn1.Unmarshal(cert.RawTBSCertificate, &tbs); err != nil {
		return ""
	}
	return tbs.Signature.Algorithm.String()
}

func keyUsage(ku x509.KeyUsage) []string {
	pairs := []struct {
		bit  x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "Цифровая подпись"},
		{x509.KeyUsageContentCommitment, "Неотказуемость"},
		{x509.KeyUsageKeyEncipherment, "Шифрование ключей"},
		{x509.KeyUsageDataEncipherment, "Шифрование данных"},
		{x509.KeyUsageKeyAgreement, "Согласование ключей"},
		{x509.KeyUsageCertSign, "Подпись сертификатов"},
		{x509.KeyUsageCRLSign, "Подпись CRL"},
		{x509.KeyUsageEncipherOnly, "Только шифрование"},
		{x509.KeyUsageDecipherOnly, "Только расшифрование"},
	}
	var out []string
	for _, p := range pairs {
		if ku&p.bit != 0 {
			out = append(out, p.name)
		}
	}
	return out
}

func extKeyUsage(cert *x509.Certificate) []string {
	var out []string
	std := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageAny:             "Любое использование",
		x509.ExtKeyUsageServerAuth:      "serverAuth (TLS-сервер)",
		x509.ExtKeyUsageClientAuth:      "clientAuth (TLS-клиент)",
		x509.ExtKeyUsageCodeSigning:     "codeSigning (подпись кода)",
		x509.ExtKeyUsageEmailProtection: "emailProtection (защита почты)",
		x509.ExtKeyUsageTimeStamping:    "timeStamping (метка времени)",
		x509.ExtKeyUsageOCSPSigning:     "OCSPSigning (подпись OCSP)",
	}
	for _, e := range cert.ExtKeyUsage {
		if s, ok := std[e]; ok {
			out = append(out, s)
		}
	}
	for _, oid := range cert.UnknownExtKeyUsage {
		s := oid.String()
		if name, ok := ekuNames[s]; ok {
			out = append(out, name)
		} else {
			out = append(out, s)
		}
	}
	return out
}

func policies(oids []asn1.ObjectIdentifier) []string {
	var out []string
	for _, oid := range oids {
		s := oid.String()
		if name, ok := policyNames[s]; ok {
			out = append(out, fmt.Sprintf("%s (%s)", name, s))
		} else {
			out = append(out, s)
		}
	}
	return out
}

// signToolString вытаскивает строковое содержимое расширения СредстваЭП.
// 111 (владелец) — UTF8String; 112 (издатель) - SEQUENCE из строк.
func signToolString(cert *x509.Certificate, oid string) string {
	for _, ext := range cert.Extensions {
		if ext.Id.String() != oid {
			continue
		}
		var s string
		if _, err := asn1.Unmarshal(ext.Value, &s); err == nil && s != "" {
			return s
		}
		var seq []string
		if _, err := asn1.Unmarshal(ext.Value, &seq); err == nil && len(seq) > 0 {
			return strings.Join(seq, "; ")
		}
		return "(не удалось разобрать значение)"
	}
	return ""
}

// otherExtensions перечисляет расширения, не показанные отдельными разделами.
func otherExtensions(cert *x509.Certificate) []extEntry {
	handled := map[string]bool{
		"2.5.29.15": true, "2.5.29.37": true, "2.5.29.19": true,
		"2.5.29.14": true, "2.5.29.35": true, "2.5.29.31": true,
		"2.5.29.32": true, "1.3.6.1.5.5.7.1.1": true,
		"1.2.643.100.111": true, "1.2.643.100.112": true,
	}
	var out []extEntry
	for _, ext := range cert.Extensions {
		oid := ext.Id.String()
		if handled[oid] {
			continue
		}
		out = append(out, extEntry{OID: oid, Name: extNames[oid], Critical: ext.Critical})
	}
	return out
}

// --- хэши ---

func sha1Sum(b []byte) []byte   { s := sha1.Sum(b); return s[:] }
func sha256Sum(b []byte) []byte { s := sha256.Sum256(b); return s[:] }

func streebog256(b []byte) []byte {
	h := gost34112012256.New()
	h.Write(b)
	return h.Sum(nil)
}

func hexColons(b []byte) string {
	const hexd = "0123456789ABCDEF"
	if len(b) == 0 {
		return ""
	}
	var sb strings.Builder
	for i, c := range b {
		if i > 0 {
			sb.WriteByte(':')
		}
		sb.WriteByte(hexd[c>>4])
		sb.WriteByte(hexd[c&0x0f])
	}
	return sb.String()
}

// --- текстовый рендер ---

func renderText(r *report) string {
	var b strings.Builder
	section := func(title string) { fmt.Fprintf(&b, "\n== %s ==\n", title) }
	kv := func(k, v string) {
		if v != "" {
			fmt.Fprintf(&b, "  %-16s %s\n", k+":", v)
		}
	}

	section("Субъект (владелец)")
	for _, n := range r.Subject {
		kv(n.Label, n.Value)
	}

	section("Издатель (УЦ)")
	for _, n := range r.Issuer {
		kv(n.Label, n.Value)
	}

	section("Срок действия")
	kv("С", r.NotBefore)
	kv("По", r.NotAfter)
	status := r.Status
	if r.Status == "действует" {
		status = fmt.Sprintf("%s (осталось дней: %d)", r.Status, r.DaysLeft)
	}
	kv("Статус", status)

	section("Алгоритм и идентификаторы")
	pk := r.PublicKeyName
	if pk == "" {
		pk = r.PublicKeyOID
	} else if r.PublicKeyBits > 0 {
		pk = fmt.Sprintf("%s, %d бит [%s]", r.PublicKeyName, r.PublicKeyBits, r.PublicKeyOID)
	}
	kv("Открытый ключ", pk)
	sig := r.SignatureName
	if sig == "" {
		sig = r.SignatureOID
	} else {
		sig = fmt.Sprintf("%s [%s]", r.SignatureName, r.SignatureOID)
	}
	kv("Подпись", sig)
	kv("Серийный (hex)", r.SerialHex)
	kv("Серийный (dec)", r.SerialDec)
	kv("Версия", fmt.Sprintf("v%d", r.Version))

	section("Отпечатки")
	kv("SHA-1", r.FpSHA1+"   (= отпечаток/thumbprint в КриптоПро)")
	kv("SHA-256", r.FpSHA256)
	kv("Streebog-256", r.FpStreebog)

	section("Использование ключа")
	for _, u := range r.KeyUsage {
		fmt.Fprintf(&b, "  - %s\n", u)
	}
	if len(r.ExtKeyUsage) > 0 {
		fmt.Fprintf(&b, "  Расширенное (EKU):\n")
		for _, u := range r.ExtKeyUsage {
			fmt.Fprintf(&b, "    - %s\n", u)
		}
	}

	section("Расширения")
	kv("Ограничения", r.BasicConstraints)
	kv("Ключ субъекта", r.SubjectKeyID)
	kv("Ключ УЦ", r.AuthorityKeyID)
	for _, p := range r.CRLPoints {
		kv("CRL", p)
	}
	for _, o := range r.OCSP {
		kv("OCSP", o)
	}
	for _, c := range r.CAIssuers {
		kv("Сертификаты УЦ", c)
	}
	for _, p := range r.Policies {
		kv("Политика", p)
	}
	kv("СредстваЭП", r.SubjectSignTool)
	kv("СредстваЭП УЦ", r.IssuerSignTool)
	for _, e := range r.OtherExtensions {
		name := e.Name
		if name == "" {
			name = "(неизвестно)"
		}
		crit := ""
		if e.Critical {
			crit = " [critical]"
		}
		fmt.Fprintf(&b, "  %s: %s%s\n", e.OID, name, crit)
	}

	return b.String()
}
