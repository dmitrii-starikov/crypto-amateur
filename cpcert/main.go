package main

import (
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ddulesov/gogost/gost28147"
	"github.com/ddulesov/gogost/gost34112012256"
	"github.com/ddulesov/gogost/gost341194"
	"github.com/ddulesov/gogost/gost3410"
)

const salt0 = "DENEFH028.760246785.IUEFHWUIO.EF"

const (
	algUnknown = iota
	algGost2001
	algGost2012_256
	algGost2012_512
)

var debug bool

func dbg(name string, b []byte) {
	if debug {
		fmt.Fprintf(os.Stderr, "DBG %s %x\n", name, b)
	}
}

func main() {
	var outPrefix string
	flag.BoolVar(&debug, "debug", false, "печатать промежуточные значения в stderr")
	flag.StringVar(&outPrefix, "o", "", "префикс файлов вывода: создаст <prefix>.cer и <prefix>.key (без -o будет склеенный PEM в stdout)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Использование: cpcert [-debug] [-o префикс] <папка-контейнера> [пароль]\n")
		fmt.Fprintf(os.Stderr, "  без -o : склеенный PEM (CERTIFICATE + PRIVATE KEY) в stdout\n")
		fmt.Fprintf(os.Stderr, "  с  -o : раздельно в <префикс>.cer и <префикс>.key\n")
	}
	flag.Parse()
	args := flag.Args()
	if len(args) < 1 {
		flag.Usage()
		os.Exit(2)
	}
	dir := args[0]
	pass := ""
	if len(args) > 1 {
		pass = args[1]
	}

	if err := run(dir, pass, outPrefix); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
}

func writePEM(path, typ string, der []byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: typ, Bytes: der})
}

func run(dir, pass, outPrefix string) error {
	header, err := os.ReadFile(filepath.Join(dir, "header.key"))
	if err != nil {
		return fmt.Errorf("read header.key: %w", err)
	}
	primaryDER, err := os.ReadFile(filepath.Join(dir, "primary.key"))
	if err != nil {
		return fmt.Errorf("read primary.key: %w", err)
	}
	masksDER, err := os.ReadFile(filepath.Join(dir, "masks.key"))
	if err != nil {
		return fmt.Errorf("read masks.key: %w", err)
	}

	alg, cert, pub8, err := parseHeader(header)
	if err != nil {
		return err
	}
	prim, err := parsePrimary(primaryDER)
	if err != nil {
		return err
	}
	mask, salt, err := parseMasks(masksDER)
	if err != nil {
		return err
	}

	priv, err := extractPriv(alg, pass, prim, mask, salt, pub8)
	if err != nil {
		return err
	}

	apk, err := buildPrivateKeyInfo(alg, priv)
	if err != nil {
		return err
	}

	if outPrefix == "" {
		// склеенный PEM в stdout
		if len(cert) > 0 {
			if err := pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: cert}); err != nil {
				return err
			}
		}
		return pem.Encode(os.Stdout, &pem.Block{Type: "PRIVATE KEY", Bytes: apk})
	}

	// раздельно по файлам
	if len(cert) > 0 {
		if err := writePEM(outPrefix+".cer", "CERTIFICATE", cert); err != nil {
			return err
		}
	}
	if err := writePEM(outPrefix+".key", "PRIVATE KEY", apk); err != nil {
		return err
	}
	return nil
}

// ASN.1: рекурсивный обход TLV (definite-length DER)

type visitFn func(level, index, class, tag int, composite bool, body []byte)

func walk(data []byte, level int, visit visitFn) {
	i, index := 0, 0
	for i < len(data) {
		if i+2 > len(data) {
			return
		}
		b0 := data[i]
		i++
		class := int(b0 >> 6)
		composite := b0&0x20 != 0
		tag := int(b0 & 0x1f)
		if tag == 0x1f {
			tag = 0
			for i < len(data) {
				x := data[i]
				i++
				tag = (tag << 7) | int(x&0x7f)
				if x&0x80 == 0 {
					break
				}
			}
		}
		if i >= len(data) {
			return
		}
		l := int(data[i])
		i++
		if l >= 0x80 {
			n := l & 0x7f
			l = 0
			for ; n > 0 && i < len(data); n-- {
				l = (l << 8) | int(data[i])
				i++
			}
		}
		if i+l > len(data) {
			return
		}
		body := data[i : i+l]
		visit(level, index, class, tag, composite, body)
		if composite {
			walk(body, level+1, visit)
		}
		i += l
		index++
	}
}

func decodeOID(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	var sb strings.Builder
	first := int(body[0])
	sb.WriteString(strconv.Itoa(first / 40))
	sb.WriteByte('.')
	sb.WriteString(strconv.Itoa(first % 40))
	v := 0
	for _, c := range body[1:] {
		v = (v << 7) | int(c&0x7f)
		if c&0x80 == 0 {
			sb.WriteByte('.')
			sb.WriteString(strconv.Itoa(v))
			v = 0
		}
	}
	return sb.String()
}

func parseHeader(data []byte) (alg int, cert, pub8 []byte, err error) {
	walk(data, 0, func(level, index, class, tag int, composite bool, body []byte) {
		if class == 2 { // context
			if tag == 10 && len(body) >= 8 {
				pub8 = append([]byte(nil), body[:8]...)
			}
			if tag == 5 {
				cert = append([]byte(nil), body...)
			}
		}
		if level == 5 && class == 0 && tag == 6 { // OID
			switch decodeOID(body) {
			case "1.2.643.2.2.30.1":
				alg = algGost2001
			case "1.2.643.7.1.1.2.2":
				alg = algGost2012_256
			case "1.2.643.7.1.1.2.3":
				alg = algGost2012_512
			}
		}
	})
	if alg == algUnknown {
		return 0, nil, nil, errors.New("неизвестный/неподдерживаемый алгоритм контейнера")
	}
	if len(pub8) < 8 {
		return 0, nil, nil, errors.New("в header.key не найден pub8")
	}
	return alg, cert, pub8, nil
}

// первый OCTET STRING на уровне 1
func firstOctetString(data []byte) []byte {
	var res []byte
	walk(data, 0, func(level, index, class, tag int, composite bool, body []byte) {
		if res == nil && class == 0 && tag == 4 && !composite {
			res = append([]byte(nil), body...)
		}
	})
	return res
}

func parsePrimary(data []byte) ([]byte, error) {
	v := firstOctetString(data)
	if v == nil {
		return nil, errors.New("primary.key: OCTET STRING не найден")
	}
	return v, nil
}

func parseMasks(data []byte) (mask, salt []byte, err error) {
	var octs [][]byte
	walk(data, 0, func(level, index, class, tag int, composite bool, body []byte) {
		if class == 0 && tag == 4 && !composite {
			octs = append(octs, append([]byte(nil), body...))
		}
	})
	if len(octs) < 2 {
		return nil, nil, errors.New("masks.key: ожидались mask и salt")
	}
	return octs[0], octs[1][:12], nil
}

// KDF

func xorConst(b []byte, c byte) []byte {
	r := make([]byte, len(b))
	for i := range b {
		r[i] = b[i] ^ c
	}
	return r
}

func pincode4(pass string) []byte {
	out := make([]byte, len(pass)*4)
	for i := 0; i < len(pass); i++ {
		out[i*4] = pass[i]
	}
	return out
}

// make2012PwdKey - KDF на Streebog-256 (используется и для 256, и для 512 ключей)
func make2012PwdKey(salt []byte, pass string) []byte {
	const size2 = 64
	pin := pincode4(pass)

	h := gost34112012256.New()
	h.Write(salt)
	h.Write(pin)
	saltPass := h.Sum(nil) // 32

	current := make([]byte, size2)
	copy(current, salt0)

	n := 2000
	if len(pass) == 0 {
		n = 2
	}
	for i := 0; i < n; i++ {
		x36 := xorConst(current, 0x36)
		x5c := xorConst(current, 0x5c)
		h := gost34112012256.New()
		h.Write(x36)
		h.Write(saltPass)
		h.Write(x5c)
		h.Write(saltPass)
		copy(current[:32], h.Sum(nil))
	}

	x36 := xorConst(current, 0x36)
	x5c := xorConst(current, 0x5c)
	h = gost34112012256.New()
	h.Write(x36[:32])
	h.Write(salt)
	h.Write(x5c[:32])
	h.Write(pin)
	copy(current[:32], h.Sum(nil))

	h = gost34112012256.New()
	h.Write(current[:32])
	return h.Sum(nil)
}

// make2001PwdKey - KDF на ГОСТ Р 34.11-94 (CryptoPro paramset)
func make2001PwdKey(salt []byte, pass string) []byte {
	const size2 = 32
	pin := pincode4(pass)
	sbox := &gost28147.SboxIdGostR341194CryptoProParamSet

	h := gost341194.New(sbox)
	h.Write(salt)
	h.Write(pin)
	saltPass := h.Sum(nil)

	current := make([]byte, size2)
	copy(current, salt0)

	n := 2000
	if len(pass) == 0 {
		n = 2
	}
	for i := 0; i < n; i++ {
		x36 := xorConst(current, 0x36)
		x5c := xorConst(current, 0x5c)
		h := gost341194.New(sbox)
		h.Write(x36)
		h.Write(saltPass)
		h.Write(x5c)
		h.Write(saltPass)
		copy(current, h.Sum(nil))
	}

	x36 := xorConst(current, 0x36)
	x5c := xorConst(current, 0x5c)
	h = gost341194.New(sbox)
	h.Write(x36)
	h.Write(salt)
	h.Write(x5c)
	h.Write(pin)
	copy(current, h.Sum(nil))

	h = gost341194.New(sbox)
	h.Write(current)
	return h.Sum(nil)
}

// извлечение приватного ключа

func reverse(b []byte) []byte {
	r := make([]byte, len(b))
	for i := range b {
		r[len(b)-1-i] = b[i]
	}
	return r
}

func extractPriv(alg int, pass string, prim, mask, salt, pub8 []byte) ([]byte, error) {
	var keySize int
	var pwdKey []byte
	var sbox *gost28147.Sbox
	var curve *gost3410.Curve

	switch alg {
	case algGost2001:
		keySize = 32
		pwdKey = make2001PwdKey(salt, pass)
		sbox = &gost28147.SboxIdGost2814789CryptoProAParamSet
		curve = gost3410.CurveIdGostR34102001CryptoProXchAParamSet()
	case algGost2012_256:
		keySize = 32
		pwdKey = make2012PwdKey(salt, pass)
		sbox = &gost28147.SboxIdtc26gost28147paramZ
		curve = gost3410.CurveIdGostR34102001CryptoProXchAParamSet()
	case algGost2012_512:
		keySize = 64
		pwdKey = make2012PwdKey(salt, pass)
		sbox = &gost28147.SboxIdtc26gost28147paramZ
		curve = gost3410.CurveIdtc26gost341012512paramSetA()
	default:
		return nil, errors.New("неподдерживаемый алгоритм")
	}
	dbg("pwd_key", pwdKey)

	// расшифровка primary (GOST 28147 ECB)
	cipher := gost28147.NewCipher(pwdKey, sbox)
	dec := make([]byte, keySize)
	for off := 0; off < keySize; off += 8 {
		cipher.Decrypt(dec[off:off+8], prim[off:off+8])
	}
	dbg("dec", dec)
	keyWithMaskBE := reverse(dec)
	dbg("key_with_mask_be", keyWithMaskBE)
	keyWithMask := new(big.Int).SetBytes(keyWithMaskBE)

	maskBE := reverse(mask[:keySize])
	dbg("mask_be", maskBE)
	maskInt := new(big.Int).SetBytes(maskBE)

	order := curve.Q
	maskInv := new(big.Int).ModInverse(maskInt, order)
	if maskInv == nil {
		return nil, errors.New("маска необратима по модулю порядка группы")
	}
	rawSecret := new(big.Int).Mul(keyWithMask, maskInv)
	rawSecret.Mod(rawSecret, order)
	dbg("raw_secret_be", rawSecret.FillBytes(make([]byte, keySize)))

	// проверка соответствия открытому ключу из контейнера
	pubX, _, err := curve.Exp(rawSecret, curve.X, curve.Y)
	if err != nil {
		return nil, fmt.Errorf("вычисление открытого ключа: %w", err)
	}
	pubXBE := pubX.FillBytes(make([]byte, keySize))
	dbg("pubX_be", pubXBE)
	pubLE := reverse(pubXBE)
	if string(pubLE[:8]) != string(pub8) {
		return nil, errors.New("invalid password (открытый ключ не сошёлся с контейнером)")
	}

	// приватный ключ в little-endian (как хранит КриптоПро)
	privBE := rawSecret.FillBytes(make([]byte, keySize))
	return reverse(privBE), nil
}

// сборка PrivateKeyInfo (шаблоны как в get-cpcert)

func buildPrivateKeyInfo(alg int, privLE []byte) ([]byte, error) {
	var tmpl []byte
	var keyOff int
	switch alg {
	case algGost2001:
		tmpl = []byte{
			0x30, 67, 2, 1, 0, 0x30, 28,
			6, 6, 42, 0x85, 3, 2, 2, 19,
			0x30, 18,
			6, 7, 42, 0x85, 3, 2, 2, 36, 0,
			6, 7, 42, 0x85, 3, 2, 2, 30, 1,
			4, 32,
		}
		keyOff = 37
	case algGost2012_256:
		tmpl = []byte{
			0x30, 70, 2, 1, 0, 0x30, 31,
			6, 8, 0x2A, 0x85, 3, 7, 1, 1, 1, 1,
			0x30, 19,
			6, 7, 42, 0x85, 3, 2, 2, 36, 0,
			6, 8, 42, 0x85, 3, 7, 1, 1, 2, 2,
			4, 32,
		}
		keyOff = 40
	case algGost2012_512:
		tmpl = []byte{
			0x30, 94, 2, 1, 0, 0x30, 23,
			6, 8, 42, 0x85, 3, 7, 1, 1, 1, 2,
			0x30, 11,
			6, 9, 42, 0x85, 3, 7, 1, 2, 1, 2, 1,
			4, 64,
		}
		keyOff = 32
	default:
		return nil, errors.New("неподдерживаемый алгоритм")
	}
	out := make([]byte, keyOff+len(privLE))
	copy(out, tmpl)
	copy(out[keyOff:], privLE)
	return out, nil
}
