// ============================================================
//
//	OHashHunt — Hash Identifier & Wordlist Cracker
//	Author  : khaled.s.haddad
//	Website : owlsec.org
//	Language: Go (stdlib only) — OWL suite
//
//	Identifies hash types by structure/length and recovers
//	plaintext from a wordlist for the digests it can compute:
//	MD4, MD5, SHA-1, SHA-224/256/384/512 and NTLM (MD4 of
//	UTF-16LE), plus salted md5/sha1/sha256 in hash:salt form.
//	The dictionary is indexed once per algorithm, so a whole
//	hash file is cracked in a single pass over the wordlist.
//	For authorized password audits, CTFs and recovery only.
//
// ============================================================
package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

// ---- OWL UI KIT (cyan "owl" house style) — stdlib only. Shared across the suite ----
const (
	R   = "\033[91m"
	GRN = "\033[92m"
	YLW = "\033[93m"
	CY  = "\033[96m"
	W   = "\033[97m"
	B   = "\033[1m"
	X   = "\033[0m"
	MG  = "\033[95m"
	DIM = "\033[2m"
	OR  = "\033[38;5;208m"
	GY  = "\033[90m"
)

var noColor = os.Getenv("NO_COLOR") != "" || !isatty()

func isatty() bool { fi, _ := os.Stdout.Stat(); return (fi.Mode() & os.ModeCharDevice) != 0 }
func col(s string, c ...string) string {
	if noColor {
		return s
	}
	return strings.Join(c, "") + s + X
}
func clear()           { fmt.Print("\033[H\033[2J") }
func rule()            { fmt.Println(col(strings.Repeat("─", 66), CY)) }
func okMsg(s string)   { fmt.Println("  " + col("[✔] ", GRN+B) + col(s, W)) }
func errMsg(s string)  { fmt.Println("  " + col("[✘] ", R+B) + col(s, R)) }
func warnMsg(s string) { fmt.Println("  " + col("[!] ", OR+B) + col(s, YLW)) }
func info(s string)    { fmt.Println("  " + col("[*] ", CY) + col(s, DIM+W)) }
func kv(k, v string)   { fmt.Println("  " + col("│  ", CY) + col(pad(k+":", 16), DIM) + col(v, W)) }

const BANNER = `
 ██████╗ ██╗  ██╗ █████╗ ███████╗██╗  ██╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗
██╔═══██╗██║  ██║██╔══██╗██╔════╝██║  ██║██║  ██║██║   ██║████╗  ██║╚══██╔══╝
██║   ██║███████║███████║███████╗███████║███████║██║   ██║██╔██╗ ██║   ██║
██║   ██║██╔══██║██╔══██║╚════██║██╔══██║██╔══██║██║   ██║██║╚██╗██║   ██║
╚██████╔╝██║  ██║██║  ██║███████║██║  ██║██║  ██║╚██████╔╝██║ ╚████║   ██║
 ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝
`

const APPNAME = "OHashHunt"
const SUITE = "Owl Password Suite"
const TAGLINE = "Hash Identifier & Wordlist Cracker"
const SUBLINE = "Identify · MD4/5 · SHA-1/224/256/384/512 · NTLM · salted · fast dictionary"
const VERSION = "1.0"
const AUTHOR = "khaled.s.haddad"
const WEBSITE = "owlsec.org"

func banner() {
	fmt.Println(col(BANNER, CY))
	fmt.Println("  " + col(SUITE+"  ", B+MG) + col("v"+VERSION, YLW))
	fmt.Println("  " + col(SUBLINE, W))
	fmt.Println()
	fmt.Println("  " + col("Developer : ", DIM) + col(AUTHOR, CY) +
		col("   |   Website : ", DIM) + col(WEBSITE, CY))
	rule()
	fmt.Println()
}

var stdin = bufio.NewReader(os.Stdin)

func prompt(label string) string {
	fmt.Print("  " + col("[»] ", YLW) + col(label+": ", W))
	s, _ := stdin.ReadString('\n')
	return strings.TrimSpace(s)
}
func pause() {
	fmt.Print(col("\n  [↩] Press Enter to continue...", YLW))
	stdin.ReadString('\n')
}
func sectionHeader(s string) {
	rule()
	fmt.Println("  " + col("⬡  "+s, B+CY))
	rule()
	fmt.Println()
}

func stripANSI(s string) string {
	var b strings.Builder
	esc := false
	for _, r := range s {
		if r == '\033' {
			esc = true
			continue
		}
		if esc {
			if r == 'm' {
				esc = false
			}
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
func vlen(s string) int { return utf8.RuneCountInString(stripANSI(s)) }
func pad(s string, n int) string {
	if l := vlen(s); l < n {
		return s + strings.Repeat(" ", n-l)
	}
	return s
}
func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n < 1 {
		return ""
	}
	return string(r[:n-1]) + "…"
}

func table(headers []string, rows [][]string) {
	w := make([]int, len(headers))
	for i, h := range headers {
		w[i] = vlen(h)
	}
	for _, r := range rows {
		for i, c := range r {
			if i < len(w) && vlen(c) > w[i] {
				w[i] = vlen(c)
			}
		}
	}
	var hb strings.Builder
	for i, h := range headers {
		hb.WriteString(col(pad(h, w[i]), CY+B))
		if i < len(headers)-1 {
			hb.WriteString(col(" │ ", CY))
		}
	}
	fmt.Println("  " + hb.String())
	seg := make([]string, len(w))
	for i := range w {
		seg[i] = strings.Repeat("─", w[i])
	}
	fmt.Println("  " + col(strings.Join(seg, "─┼─"), CY))
	for _, r := range rows {
		var rb strings.Builder
		for i := range headers {
			v := ""
			if i < len(r) {
				v = r[i]
			}
			rb.WriteString(pad(col(v, W), w[i]))
			if i < len(headers)-1 {
				rb.WriteString(col(" │ ", CY))
			}
		}
		fmt.Println("  " + rb.String())
	}
}

// ============================================================
//  MD4 (RFC 1320) — from scratch, for NTLM support
// ============================================================

func rotl(x uint32, n uint) uint32 { return (x << n) | (x >> (32 - n)) }

func md4Sum(msg []byte) [16]byte {
	a := uint32(0x67452301)
	b := uint32(0xefcdab89)
	c := uint32(0x98badcfe)
	d := uint32(0x10325476)

	ml := uint64(len(msg)) * 8
	msg = append(append([]byte{}, msg...), 0x80)
	for len(msg)%64 != 56 {
		msg = append(msg, 0x00)
	}
	lenBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(lenBytes, ml)
	msg = append(msg, lenBytes...)

	f := func(x, y, z uint32) uint32 { return (x & y) | (^x & z) }
	g := func(x, y, z uint32) uint32 { return (x & y) | (x & z) | (y & z) }
	h := func(x, y, z uint32) uint32 { return x ^ y ^ z }

	for i := 0; i < len(msg); i += 64 {
		var Xb [16]uint32
		for j := 0; j < 16; j++ {
			Xb[j] = binary.LittleEndian.Uint32(msg[i+j*4 : i+j*4+4])
		}
		aa, bb, cc, dd := a, b, c, d

		r1s := []uint{3, 7, 11, 19}
		for j := 0; j < 16; j++ {
			k := j
			s := r1s[j%4]
			switch j % 4 {
			case 0:
				a = rotl(a+f(b, c, d)+Xb[k], s)
			case 1:
				d = rotl(d+f(a, b, c)+Xb[k], s)
			case 2:
				c = rotl(c+f(d, a, b)+Xb[k], s)
			case 3:
				b = rotl(b+f(c, d, a)+Xb[k], s)
			}
		}
		r2k := []int{0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15}
		r2s := []uint{3, 5, 9, 13}
		for j := 0; j < 16; j++ {
			k := r2k[j]
			s := r2s[j%4]
			switch j % 4 {
			case 0:
				a = rotl(a+g(b, c, d)+Xb[k]+0x5a827999, s)
			case 1:
				d = rotl(d+g(a, b, c)+Xb[k]+0x5a827999, s)
			case 2:
				c = rotl(c+g(d, a, b)+Xb[k]+0x5a827999, s)
			case 3:
				b = rotl(b+g(c, d, a)+Xb[k]+0x5a827999, s)
			}
		}
		r3k := []int{0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15}
		r3s := []uint{3, 9, 11, 15}
		for j := 0; j < 16; j++ {
			k := r3k[j]
			s := r3s[j%4]
			switch j % 4 {
			case 0:
				a = rotl(a+h(b, c, d)+Xb[k]+0x6ed9eba1, s)
			case 1:
				d = rotl(d+h(a, b, c)+Xb[k]+0x6ed9eba1, s)
			case 2:
				c = rotl(c+h(d, a, b)+Xb[k]+0x6ed9eba1, s)
			case 3:
				b = rotl(b+h(c, d, a)+Xb[k]+0x6ed9eba1, s)
			}
		}
		a += aa
		b += bb
		c += cc
		d += dd
	}
	var out [16]byte
	binary.LittleEndian.PutUint32(out[0:], a)
	binary.LittleEndian.PutUint32(out[4:], b)
	binary.LittleEndian.PutUint32(out[8:], c)
	binary.LittleEndian.PutUint32(out[12:], d)
	return out
}

// NTLM hash = MD4(UTF-16LE(password))
func ntlmHash(pw string) string {
	u := utf16.Encode([]rune(pw))
	buf := make([]byte, len(u)*2)
	for i, r := range u {
		binary.LittleEndian.PutUint16(buf[i*2:], r)
	}
	s := md4Sum(buf)
	return hex.EncodeToString(s[:])
}

func md5Hex(s string) string    { h := md5.Sum([]byte(s)); return hex.EncodeToString(h[:]) }
func sha1Hex(s string) string   { h := sha1.Sum([]byte(s)); return hex.EncodeToString(h[:]) }
func sha224Hex(s string) string { h := sha256.Sum224([]byte(s)); return hex.EncodeToString(h[:]) }
func sha256Hex(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func sha384Hex(s string) string { h := sha512.Sum384([]byte(s)); return hex.EncodeToString(h[:]) }
func sha512Hex(s string) string { h := sha512.Sum512([]byte(s)); return hex.EncodeToString(h[:]) }
func md4Hex(s string) string    { h := md4Sum([]byte(s)); return hex.EncodeToString(h[:]) }

type algo struct {
	name   string
	hexLen int
	fn     func(string) string
}

var algos = []algo{
	{"md5", 32, md5Hex},
	{"ntlm", 32, ntlmHash},
	{"md4", 32, md4Hex},
	{"sha1", 40, sha1Hex},
	{"sha224", 56, sha224Hex},
	{"sha256", 64, sha256Hex},
	{"sha384", 96, sha384Hex},
	{"sha512", 128, sha512Hex},
}

func algoByName(n string) *algo {
	n = strings.ToLower(strings.TrimSpace(n))
	for i := range algos {
		if algos[i].name == n {
			return &algos[i]
		}
	}
	return nil
}

// algosForLen returns the candidate algorithms that produce a digest of the
// given hex length (used for auto mode).
func algosForLen(n int) []*algo {
	var out []*algo
	for i := range algos {
		if algos[i].hexLen == n {
			out = append(out, &algos[i])
		}
	}
	return out
}

// ============================================================
//  Hash identification
// ============================================================

func isHex(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range strings.ToLower(s) {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

type ident struct {
	Candidates []string
	Crackable  []string // algo names this tool can attempt
	Note       string
}

func identify(hash string) ident {
	h := strings.TrimSpace(hash)
	res := ident{}
	switch {
	case strings.HasPrefix(h, "$2a$"), strings.HasPrefix(h, "$2b$"), strings.HasPrefix(h, "$2y$"):
		res.Candidates = []string{"bcrypt (Blowfish, modular crypt)"}
		res.Note = "adaptive — not supported for cracking here"
		return res
	case strings.HasPrefix(h, "$1$"):
		res.Candidates = []string{"md5crypt ($1$)"}
		return res
	case strings.HasPrefix(h, "$5$"):
		res.Candidates = []string{"sha256crypt ($5$)"}
		return res
	case strings.HasPrefix(h, "$6$"):
		res.Candidates = []string{"sha512crypt ($6$)"}
		return res
	case strings.HasPrefix(h, "$argon2"):
		res.Candidates = []string{"Argon2 (PHC string)"}
		return res
	case strings.HasPrefix(h, "$pbkdf2"), strings.HasPrefix(h, "$pbkdf2-"):
		res.Candidates = []string{"PBKDF2 (PHC string)"}
		return res
	case strings.HasPrefix(h, "{SSHA}"):
		res.Candidates = []string{"SSHA (salted SHA-1, LDAP)"}
		return res
	case strings.HasPrefix(h, "{SHA}"):
		res.Candidates = []string{"SHA-1 (LDAP, base64)"}
		return res
	}
	if i := strings.IndexByte(h, ':'); i > 0 {
		left := h[:i]
		if isHex(left) {
			res.Note = "looks salted (hash:salt) — try salted cracking"
			switch len(left) {
			case 32:
				res.Candidates = []string{"salted MD5 (hash:salt)", "NTLM:salt", "LM:NTLM pair"}
				res.Crackable = []string{"md5", "sha1", "sha256"}
			case 40:
				res.Candidates = []string{"salted SHA-1 (hash:salt)"}
				res.Crackable = []string{"md5", "sha1", "sha256"}
			case 64:
				res.Candidates = []string{"salted SHA-256 (hash:salt)"}
				res.Crackable = []string{"md5", "sha1", "sha256"}
			default:
				res.Candidates = []string{"hash:salt (unknown left length)"}
			}
			return res
		}
	}
	if !isHex(h) {
		res.Candidates = []string{"non-hex / unknown encoding (maybe base64 or plain)"}
		return res
	}
	switch len(h) {
	case 16:
		res.Candidates = []string{"MySQL<=4.0 / CRC-64 / half-MD5"}
	case 32:
		res.Candidates = []string{"MD5", "NTLM", "MD4", "LM", "MD2"}
		res.Crackable = []string{"md5", "ntlm", "md4"}
	case 40:
		res.Candidates = []string{"SHA-1", "RIPEMD-160", "SHA0"}
		res.Crackable = []string{"sha1"}
	case 56:
		res.Candidates = []string{"SHA-224", "SHA3-224"}
		res.Crackable = []string{"sha224"}
	case 64:
		res.Candidates = []string{"SHA-256", "SHA3-256", "BLAKE2s-256", "Keccak-256"}
		res.Crackable = []string{"sha256"}
	case 96:
		res.Candidates = []string{"SHA-384", "SHA3-384"}
		res.Crackable = []string{"sha384"}
	case 128:
		res.Candidates = []string{"SHA-512", "SHA3-512", "Whirlpool", "BLAKE2b-512"}
		res.Crackable = []string{"sha512"}
	default:
		res.Candidates = []string{fmt.Sprintf("unknown (%d hex chars)", len(h))}
	}
	return res
}

// ============================================================
//  Cracking engine — index the wordlist once per algorithm
// ============================================================

type target struct {
	Raw   string
	Hash  string // lowercase hex digest
	Salt  string // "" if unsalted
	Plain string
	Algo  string
}

const (
	saltSuffix = "suffix" // hash = H(word + salt)
	saltPrefix = "prefix" // hash = H(salt + word)
	saltBoth   = "both"
)

// crackBatch recovers plaintexts for a set of targets with a single pass over
// the wordlist per algorithm (for unsalted targets). Salted targets are
// handled per-target. Returns the number solved.
func crackBatch(targets []*target, words []string, chosen []*algo, saltMode string, onWord func(done, total int)) int {
	solved := 0
	// When no algorithm is forced, try them all; the per-length filter below
	// keeps each pass cheap.
	tryAlgos := chosen
	if len(tryAlgos) == 0 {
		for i := range algos {
			tryAlgos = append(tryAlgos, &algos[i])
		}
	}
	// --- unsalted: build a lookup of outstanding hashes per algorithm ---
	for _, a := range tryAlgos {
		want := map[string]*target{}
		for _, t := range targets {
			if t.Plain != "" || t.Salt != "" {
				continue
			}
			if len(t.Hash) == a.hexLen {
				want[t.Hash] = t
			}
		}
		if len(want) == 0 {
			continue
		}
		for i, wd := range words {
			if onWord != nil && i%50000 == 0 {
				onWord(i, len(words))
			}
			hh := a.fn(wd)
			if t, ok := want[hh]; ok {
				t.Plain = wd
				t.Algo = a.name
				delete(want, hh)
				solved++
				if len(want) == 0 {
					break
				}
			}
		}
	}
	// --- salted: H(word±salt) per target ---
	for _, t := range targets {
		if t.Plain != "" || t.Salt == "" {
			continue
		}
		cand := chosen
		if len(cand) == 0 {
			cand = algosForLen(len(t.Hash))
		}
		for _, a := range cand {
			if len(t.Hash) != a.hexLen {
				continue
			}
			for _, wd := range words {
				var variants []string
				switch saltMode {
				case saltPrefix:
					variants = []string{a.fn(t.Salt + wd)}
				case saltSuffix:
					variants = []string{a.fn(wd + t.Salt)}
				default:
					variants = []string{a.fn(wd + t.Salt), a.fn(t.Salt + wd)}
				}
				for _, v := range variants {
					if v == t.Hash {
						t.Plain = wd
						t.Algo = a.name + "+salt"
						solved++
						break
					}
				}
				if t.Plain != "" {
					break
				}
			}
			if t.Plain != "" {
				break
			}
		}
	}
	return solved
}

func parseTarget(raw string) *target {
	raw = strings.TrimSpace(raw)
	t := &target{Raw: raw}
	if i := strings.IndexByte(raw, ':'); i > 0 && isHex(raw[:i]) {
		t.Hash = strings.ToLower(raw[:i])
		t.Salt = raw[i+1:]
	} else {
		t.Hash = strings.ToLower(raw)
	}
	return t
}

func loadLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		out = append(out, strings.TrimRight(sc.Text(), "\r\n"))
	}
	return out, sc.Err()
}

// ============================================================
//  Actions
// ============================================================

func renderIdentify(h string, id ident) {
	kv("Input", trunc(h, 60))
	kv("Length", strconv.Itoa(len(h))+" chars")
	fmt.Println()
	okMsg("Likely candidates (most probable first):")
	for i, c := range id.Candidates {
		tag := ""
		if i == 0 {
			tag = col("  (best guess)", GRN)
		}
		fmt.Println("   " + col("•", CY) + " " + col(c, W) + tag)
	}
	if id.Note != "" {
		fmt.Println()
		info(id.Note)
	}
	if len(id.Crackable) > 0 {
		info("Crackable here via wordlist: " + strings.Join(id.Crackable, ", "))
	}
}

func uiIdentify() {
	sectionHeader("Identify hash type")
	h := prompt("hash to identify")
	if h == "" {
		warnMsg("Nothing entered.")
		return
	}
	fmt.Println()
	renderIdentify(h, identify(h))
}

func uiCompute() {
	sectionHeader("Compute digests of a string")
	s := prompt("input string")
	fmt.Println()
	okMsg("Digests of: " + col(s, CY))
	fmt.Println()
	rows := [][]string{}
	for _, a := range algos {
		rows = append(rows, []string{a.name, a.fn(s)})
	}
	table([]string{"Algorithm", "Digest"}, rows)
}

func chooseAlgos(name string, sampleLen int) ([]*algo, error) {
	if name == "" || name == "auto" {
		c := algosForLen(sampleLen)
		if len(c) == 0 {
			return nil, fmt.Errorf("cannot auto-detect algorithm from length %d; pass one explicitly", sampleLen)
		}
		return c, nil
	}
	a := algoByName(name)
	if a == nil {
		return nil, fmt.Errorf("unsupported algorithm %q (have: %s)", name, algoNames())
	}
	return []*algo{a}, nil
}

func algoNames() string {
	var n []string
	for _, a := range algos {
		n = append(n, a.name)
	}
	return strings.Join(n, ", ")
}

func uiCrackOne() {
	sectionHeader("Crack a single hash")
	hraw := prompt("hash (or hash:salt)")
	if hraw == "" {
		warnMsg("Nothing entered.")
		return
	}
	a := prompt("algorithm (" + algoNames() + ", blank=auto)")
	wl := prompt("wordlist file path")
	words, err := loadLines(wl)
	if err != nil {
		errMsg(err.Error())
		return
	}
	t := parseTarget(hraw)
	chosen, err := chooseAlgos(a, len(t.Hash))
	if err != nil {
		errMsg(err.Error())
		return
	}
	fmt.Println()
	info(fmt.Sprintf("Loaded %s words. Algorithms: %s%s", humanInt(len(words)), algoLabel(chosen), saltLabel(t)))
	start := time.Now()
	crackBatch([]*target{t}, words, chosen, saltBoth, spinner())
	fmt.Print("\r\033[K")
	fmt.Println()
	if t.Plain != "" {
		okMsg("CRACKED")
		fmt.Println()
		table([]string{"Field", "Value"}, [][]string{
			{"Algorithm", t.Algo},
			{"Plaintext", col(t.Plain, GRN+B)},
			{"Hash", t.Hash},
			{"Salt", def(t.Salt, "(none)")},
			{"Time", time.Since(start).Round(time.Millisecond).String()},
		})
	} else {
		errMsg("Not found in wordlist")
		info("Tried " + humanInt(len(words)) + " words · " + time.Since(start).Round(time.Millisecond).String())
	}
}

func uiCrackFile() {
	sectionHeader("Crack a hash file")
	hf := prompt("hash file (one per line, hash or hash:salt)")
	wl := prompt("wordlist file path")
	hashes, err := loadLines(hf)
	if err != nil {
		errMsg(err.Error())
		return
	}
	words, err := loadLines(wl)
	if err != nil {
		errMsg(err.Error())
		return
	}
	var targets []*target
	for _, raw := range hashes {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		targets = append(targets, parseTarget(raw))
	}
	if len(targets) == 0 {
		warnMsg("No hashes to crack.")
		return
	}
	fmt.Println()
	info(fmt.Sprintf("Cracking %d hashes against %s words (single pass per algorithm) ...", len(targets), humanInt(len(words))))
	start := time.Now()
	n := crackBatch(targets, words, nil, saltBoth, spinner())
	fmt.Print("\r\033[K")
	fmt.Println()
	rows := [][]string{}
	for _, t := range targets {
		if t.Plain != "" {
			rows = append(rows, []string{trunc(t.Hash, 24), t.Algo, col(t.Plain, GRN)})
		} else {
			rows = append(rows, []string{trunc(t.Hash, 24), "?", col("[not found]", GY)})
		}
	}
	table([]string{"Hash", "Algo", "Plaintext"}, rows)
	fmt.Println()
	okMsg(fmt.Sprintf("Cracked %d / %d · %s", n, len(targets), time.Since(start).Round(time.Millisecond)))
}

func spinner() func(done, total int) {
	frames := []rune{'⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'}
	i := 0
	if noColor || !isatty() {
		return nil
	}
	return func(done, total int) {
		pct := 0
		if total > 0 {
			pct = done * 100 / total
		}
		fmt.Printf("\r  %s %d%%", col(string(frames[i%len(frames)]), CY), pct)
		i++
	}
}

func def(s, d string) string {
	if strings.TrimSpace(s) == "" {
		return d
	}
	return s
}
func algoLabel(c []*algo) string {
	var n []string
	for _, a := range c {
		n = append(n, a.name)
	}
	return strings.Join(n, "/")
}
func saltLabel(t *target) string {
	if t.Salt != "" {
		return "  (salted)"
	}
	return ""
}
func humanInt(n int) string {
	s := strconv.Itoa(n)
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	return string(out)
}

type menuItem struct {
	name string
	desc string
	fn   func()
}

var menuItems = []menuItem{
	{"Identify hash", "Guess the type by structure/length", uiIdentify},
	{"Crack single hash", "Recover one hash with a wordlist", uiCrackOne},
	{"Crack hash file", "Batch crack, one pass per algorithm", uiCrackFile},
	{"Compute digests", "All algorithms of a string (incl. NTLM)", uiCompute},
}

func mainMenu() {
	for {
		clear()
		banner()
		fmt.Println("  " + col("⬡  Main Menu", B+CY))
		fmt.Println()
		for i, m := range menuItems {
			fmt.Println("  " + col(pad(fmt.Sprintf("[%d]", i+1), 4), CY+B) + "  " +
				col(pad(m.name, 20), W) + col("─ "+m.desc, DIM))
		}
		fmt.Println()
		fmt.Println("  " + col(pad("[H]", 4), YLW+B) + "  " + col(pad("Help & Usage", 20), W) + col("─ How to use, every option, CLI flags & examples", DIM))
		fmt.Println("  " + col(pad("[0]", 4), R+B) + "  " + col(pad("Exit", 20), W) + col("─ Quit "+APPNAME, DIM))
		fmt.Println()
		rule()
		c := strings.TrimLeft(prompt("Select option"), "0")
		if c == "" {
			clear()
			okMsg("Goodbye.")
			return
		}
		if strings.EqualFold(c, "h") || strings.EqualFold(c, "help") || c == "?" {
			tuiHelp()
			continue
		}
		n, err := strconv.Atoi(c)
		if err != nil || n < 1 || n > len(menuItems) {
			errMsg("Unknown option")
			pause()
			continue
		}
		clear()
		banner()
		menuItems[n-1].fn()
		pause()
	}
}

// ============================================================
//  CLI
// ============================================================

func usage() {
	banner()
	sec := func(t string) { fmt.Println("  " + col(t, CY+B)) }
	sec("USAGE")
	fmt.Println("    " + APPNAME + " [flags]            (no flags → interactive TUI)")
	fmt.Println()
	sec("DESCRIPTION")
	fmt.Println("    Hash identifier + single-pass wordlist cracker. Algorithms: " + algoNames() + ".")
	fmt.Println("    Salts supported (hash:salt). For authorized password-strength audits and CTFs.")
	fmt.Println()
	sec("IDENTIFY / COMPUTE")
	fmt.Println("    --identify HASH   print the hash-type guess and exit")
	fmt.Println("    --compute STR     print all digests of STR and exit")
	fmt.Println()
	sec("CRACK")
	fmt.Println("    --hash HASH       single target (accepts hash:salt)")
	fmt.Println("    --hashfile PATH   file of hashes, one per line")
	fmt.Println("    --wordlist PATH   dictionary file (required to crack)")
	fmt.Println("    --algo NAME       force algorithm (" + algoNames() + "); default auto by length")
	fmt.Println("    --salt-mode M     prefix | suffix | both (default both)")
	fmt.Println()
	sec("OUTPUT")
	fmt.Println("    --json            machine-readable output")
	fmt.Println("    --no-color        disable ANSI colour")
	fmt.Println()
	sec("GENERAL")
	fmt.Println("    --demo  --selftest  --version  -h/--help")
	fmt.Println()
	sec("EXAMPLES")
	fmt.Println("    " + APPNAME + " --identify 5f4dcc3b5aa765d61d8327deb882cf99")
	fmt.Println("    " + APPNAME + " --compute \"correct horse\"")
	fmt.Println("    " + APPNAME + " --hash 5f4dcc3b5aa765d61d8327deb882cf99 --wordlist rockyou.txt")
	fmt.Println("    " + APPNAME + " --hashfile dump.txt --wordlist rockyou.txt --algo ntlm")
	fmt.Println("    " + APPNAME + " --hash 'd41...:s4lt' --wordlist words.txt --salt-mode suffix")
	fmt.Println("    " + APPNAME + " --hashfile dump.txt --wordlist words.txt --json > cracked.json")
	fmt.Println()
	rule()
}

func main() { os.Exit(run()) }

func run() int {
	fs := flag.NewFlagSet(APPNAME, flag.ContinueOnError)
	fs.Usage = usage
	var (
		identFlag = fs.String("identify", "", "")
		compute   = fs.String("compute", "", "")
		hash      = fs.String("hash", "", "")
		hashfile  = fs.String("hashfile", "", "")
		wordlist  = fs.String("wordlist", "", "")
		algoFlag  = fs.String("algo", "", "")
		saltMode  = fs.String("salt-mode", "both", "")
		jsonOut   = fs.Bool("json", false, "")
		nocol     = fs.Bool("no-color", false, "")
		self      = fs.Bool("selftest", false, "")
		demo      = fs.Bool("demo", false, "")
		ver       = fs.Bool("version", false, "")
	)
	if err := fs.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *nocol {
		noColor = true
	}
	if *ver {
		fmt.Printf("%s %s\n", APPNAME, VERSION)
		return 0
	}
	if *self {
		return selftest()
	}
	if *demo {
		return demoRun()
	}
	fail := func(err error) int { errMsg(err.Error()); return 1 }

	if *identFlag != "" {
		id := identify(*identFlag)
		if *jsonOut {
			emitJSON(map[string]interface{}{"hash": *identFlag, "length": len(*identFlag), "candidates": id.Candidates, "crackable": id.Crackable, "note": id.Note})
			return 0
		}
		renderIdentify(*identFlag, id)
		return 0
	}

	if *compute != "" {
		if *jsonOut {
			m := map[string]string{}
			for _, a := range algos {
				m[a.name] = a.fn(*compute)
			}
			emitJSON(m)
			return 0
		}
		rows := [][]string{}
		for _, a := range algos {
			rows = append(rows, []string{a.name, a.fn(*compute)})
		}
		table([]string{"Algorithm", "Digest"}, rows)
		return 0
	}

	if *hash != "" || *hashfile != "" {
		if *wordlist == "" {
			return fail(errors.New("--wordlist is required to crack"))
		}
		words, err := loadLines(*wordlist)
		if err != nil {
			return fail(err)
		}
		var targets []*target
		if *hash != "" {
			targets = append(targets, parseTarget(*hash))
		}
		if *hashfile != "" {
			lines, err := loadLines(*hashfile)
			if err != nil {
				return fail(err)
			}
			for _, l := range lines {
				if strings.TrimSpace(l) != "" {
					targets = append(targets, parseTarget(l))
				}
			}
		}
		var chosen []*algo
		if *algoFlag != "" {
			a := algoByName(*algoFlag)
			if a == nil {
				return fail(fmt.Errorf("unsupported algorithm %q", *algoFlag))
			}
			chosen = []*algo{a}
		}
		sm := strings.ToLower(*saltMode)
		n := crackBatch(targets, words, chosen, sm, nil)
		if *jsonOut {
			var out []map[string]string
			for _, t := range targets {
				out = append(out, map[string]string{"hash": t.Hash, "salt": t.Salt, "plaintext": t.Plain, "algo": t.Algo})
			}
			emitJSON(map[string]interface{}{"solved": n, "total": len(targets), "results": out})
			return 0
		}
		rows := [][]string{}
		for _, t := range targets {
			p := col("[not found]", GY)
			al := "?"
			if t.Plain != "" {
				p = col(t.Plain, GRN)
				al = t.Algo
			}
			rows = append(rows, []string{trunc(t.Hash, 24), al, p})
		}
		table([]string{"Hash", "Algo", "Plaintext"}, rows)
		okMsg(fmt.Sprintf("Cracked %d / %d", n, len(targets)))
		if n < len(targets) {
			return 1
		}
		return 0
	}

	mainMenu()
	return 0
}

func emitJSON(v interface{}) {
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(b))
}

// ============================================================
//  Self-test & demo
// ============================================================

func selftest() int {
	pass, fail := 0, 0
	check := func(name string, cond bool, detail string) {
		if cond {
			pass++
			okMsg(name)
		} else {
			fail++
			errMsg(name + " — " + detail)
		}
	}
	sectionHeader("OHashHunt self-test")

	// Known cryptographic test vectors.
	check("md5(abc)", md5Hex("abc") == "900150983cd24fb0d6963f7d28e17f72", md5Hex("abc"))
	check("sha1(abc)", sha1Hex("abc") == "a9993e364706816aba3e25717850c26c9cd0d89d", sha1Hex("abc"))
	check("sha224(abc)", sha224Hex("abc") == "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7", sha224Hex("abc"))
	check("sha256(abc)", sha256Hex("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", sha256Hex("abc"))
	check("sha384(abc)", sha384Hex("abc") == "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7", sha384Hex("abc"))
	check("sha512(abc)", strings.HasPrefix(sha512Hex("abc"), "ddaf35a193617abacc417349ae20413"), sha512Hex("abc"))
	check("md4(empty)", md4Hex("") == "31d6cfe0d16ae931b73c59d7e0c089c0", md4Hex(""))
	check("md4(abc)", md4Hex("abc") == "a448017aaf21d8525fc10ae87aa6729d", md4Hex("abc"))
	check("ntlm(password)", ntlmHash("password") == "8846f7eaee8fb117ad06bdd830b7586c", ntlmHash("password"))

	// Identification.
	check("identify md5-len", contains(identify("5f4dcc3b5aa765d61d8327deb882cf99").Candidates, "MD5"), "")
	check("identify sha1-len", contains(identify(sha1Hex("x")).Candidates, "SHA-1"), "")
	check("identify bcrypt", contains(identify("$2b$12$abcdefghijklmnopqrstuv").Candidates, "bcrypt (Blowfish, modular crypt)"), "")
	check("identify salted", strings.Contains(identify("5f4dcc3b5aa765d61d8327deb882cf99:na").Note, "salted"), "")

	// Cracking (batch, single pass per algo).
	words := []string{"foo", "bar", "password", "letmein", "admin", "hunter2"}
	t1 := parseTarget(md5Hex("password"))
	t2 := parseTarget(sha256Hex("hunter2"))
	t3 := parseTarget(ntlmHash("admin"))
	n := crackBatch([]*target{t1, t2, t3}, words, nil, saltBoth, nil)
	check("batch solved all 3", n == 3, strconv.Itoa(n))
	check("md5 password", t1.Plain == "password" && t1.Algo == "md5", t1.Plain+"/"+t1.Algo)
	check("sha256 hunter2", t2.Plain == "hunter2" && t2.Algo == "sha256", t2.Plain+"/"+t2.Algo)
	check("ntlm admin", t3.Plain == "admin" && t3.Algo == "ntlm", t3.Plain+"/"+t3.Algo)

	// Salted crack: H(word+salt).
	ts := &target{Raw: "x", Hash: md5Hex("letmein" + "s4lt"), Salt: "s4lt"}
	crackBatch([]*target{ts}, words, []*algo{algoByName("md5")}, saltSuffix, nil)
	check("salted md5 suffix", ts.Plain == "letmein", ts.Plain)

	// Not-found path.
	tn := parseTarget(md5Hex("not-in-list-zzz"))
	crackBatch([]*target{tn}, words, nil, saltBoth, nil)
	check("miss stays empty", tn.Plain == "", tn.Plain)

	fmt.Println()
	if fail == 0 {
		okMsg(fmt.Sprintf("All %d checks passed.", pass))
		return 0
	}
	errMsg(fmt.Sprintf("%d passed, %d failed.", pass, fail))
	return 1
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func demoRun() int {
	clear()
	banner()
	sectionHeader("Demo — identify, compute, crack")
	secret := "hunter2"
	info("Secret plaintext for the demo: " + col(secret, CY))
	fmt.Println()
	okMsg("Digests:")
	rows := [][]string{}
	for _, a := range algos {
		rows = append(rows, []string{a.name, a.fn(secret)})
	}
	table([]string{"Algorithm", "Digest"}, rows)
	fmt.Println()
	h := md5Hex(secret)
	okMsg("Identify " + trunc(h, 20) + " →")
	renderIdentify(h, identify(h))
	fmt.Println()
	words := []string{"123456", "letmein", "hunter2", "trustno1"}
	targets := []*target{parseTarget(md5Hex(secret)), parseTarget(ntlmHash("letmein"))}
	n := crackBatch(targets, words, nil, saltBoth, nil)
	okMsg(fmt.Sprintf("Cracked %d/%d from a %d-word list:", n, len(targets), len(words)))
	tr := [][]string{}
	for _, t := range targets {
		tr = append(tr, []string{trunc(t.Hash, 20), t.Algo, col(t.Plain, GRN)})
	}
	table([]string{"Hash", "Algo", "Plaintext"}, tr)
	return 0
}

// ---------------------------------------------------------------------------
// Help & Usage  (interactive menu [H])
// Page 1: in-app guide (what the tool does, every menu option, tips).
// Page 2: the full command-line reference (same text as --help).
// ---------------------------------------------------------------------------

type owlHelpItem struct{ key, text string }

func owlHelpWrap(s string, width int) []string {
	var out []string
	for _, para := range strings.Split(s, "\n") {
		words := strings.Fields(para)
		if len(words) == 0 {
			out = append(out, "")
			continue
		}
		cur := ""
		for _, w := range words {
			if cur != "" && len([]rune(cur))+1+len([]rune(w)) > width {
				out = append(out, cur)
				cur = w
			} else if cur == "" {
				cur = w
			} else {
				cur += " " + w
			}
		}
		out = append(out, cur)
	}
	return out
}

func owlHelpTitle(t string) {
	fmt.Println()
	fmt.Println("  " + col("▸ "+t, B+CY))
}

func owlHelpPara(lines []string) {
	for _, l := range lines {
		for _, w := range owlHelpWrap(l, 60) {
			fmt.Println("    " + col(w, W))
		}
	}
}

func owlHelpRows(items []owlHelpItem) {
	kw := 0
	for _, it := range items {
		if n := len([]rune(it.key)); n > kw {
			kw = n
		}
	}
	for _, it := range items {
		k := "[" + it.key + "]" + strings.Repeat(" ", kw-len([]rune(it.key)))
		for i, w := range owlHelpWrap(it.text, 56-kw) {
			if i == 0 {
				fmt.Println("    " + col(k, YLW+B) + "  " + col(w, W))
			} else {
				fmt.Println("    " + strings.Repeat(" ", kw+2) + "  " + col(w, W))
			}
		}
	}
}

func owlHelpRule() { fmt.Println(col(strings.Repeat("─", 66), CY)) }

func tuiHelp() {
	clear()
	banner()
	owlHelpRule()
	fmt.Println("  " + col("⬡  Help & Usage — "+APPNAME, B+CY))
	owlHelpRule()
	owlHelpTitle("WHAT IT DOES")
	owlHelpPara(owlHelpAbout)
	owlHelpTitle("HOW TO USE THE MENU")
	owlHelpPara(owlHelpFlow)
	owlHelpTitle("MENU OPTIONS")
	owlHelpRows(owlHelpMenu)
	owlHelpTitle("TIPS")
	owlHelpRows(owlHelpTips)
	fmt.Println()
	owlHelpRule()
	fmt.Println("  " + col("Next page: command-line flags & copy-paste examples", DIM))
	pause()
	clear()
	owlHelpCLI()
	fmt.Println()
	fmt.Println("  " + col("Tip: the same reference is printed by  "+APPNAME+" --help", DIM))
	pause()
}

var owlHelpAbout = []string{
	"OHashHunt identifies hash types and recovers (cracks) them with a wordlist, for password-strength audits and CTFs. Given a hash it guesses the algorithm from its length and structure, then tries every word in your dictionary. It supports md5, ntlm, md4, sha1, sha224, sha256, sha384 and sha512, with optional salts.",
	"Cracking is single-pass and fast: the wordlist is read once and every target of the same algorithm is tested together. It can also print all digests of a string, which is handy for making test hashes.",
}

var owlHelpFlow = []string{
	"Type the number of an option and press Enter. Use [1] to identify an unknown hash, then [2] or [3] with a wordlist to crack it. [H] opens this help, [0] or a blank line quits.",
	"You need a wordlist file (one candidate per line), e.g. rockyou.txt. The tool never guesses passwords on its own.",
}

var owlHelpMenu = []owlHelpItem{
	{"1", "Identify hash: paste a hash. Lists the most likely algorithms (by length and charset) and which of them this tool can crack."},
	{"2", "Crack single hash: enter the hash (or hash:salt), the algorithm (blank = auto-detect by length) and the wordlist path. Prints the password if a word matches."},
	{"3", "Crack hash file: enter a file of hashes (one per line) and a wordlist. Cracks them all in one pass per algorithm. Fastest for large lists."},
	{"4", "Compute digests: enter a string to see its md5, ntlm, md4, sha1 ... digests. Useful to create known hashes for testing."},
}

var owlHelpTips = []owlHelpItem{
	{"*", "Auto-detection goes by length, so md5 and ntlm (both 32 hex) can be confused. If a crack fails, force the type with the algorithm option (or --algo on the CLI)."},
	{"*", "For salted hashes, write them as hash:salt and set --salt-mode prefix | suffix | both to control how the salt is combined."},
	{"*", "This recovers only passwords already in your wordlist. A strong, unique password will not be found — that is the point of the audit. Use only on hashes you are authorised to test."},
}

func owlHelpCLI() { usage() }
