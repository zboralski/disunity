package signal

import (
	"math"
	"regexp"
	"strings"
)

// Categories for string signal classification.
const (
	CatURL        = "url"
	CatHost       = "host"
	CatEncryption = "encryption"
	CatAuth       = "auth"
	CatNet        = "net"
	CatFileExt    = "file"
	CatBase64Key  = "base64"

	// Suspicious mobile behavior categories.
	CatSIM         = "sim"         // SIM card, IMEI, carrier, MCC/MNC
	CatSMS         = "sms"         // SMS read/send
	CatContacts    = "contacts"    // Contact list access
	CatLocation    = "location"    // GPS, geolocation, geofence
	CatDeviceInfo  = "device"      // Device ID, fingerprinting
	CatCloaking    = "cloaking"    // Keyword/locale gating, redirect tricks
	CatDataCollect = "data"        // Bulk data harvesting
	CatCamera      = "camera"      // Camera access
	CatWebView     = "webview"     // WebView loadUrl, evaluateJavascript, JS bridge
	CatBlockchain  = "blockchain"  // Wallet, mnemonic, seed phrase, blockchain, NFT
	CatGambling    = "gambling"    // Betting, casino, slots, lottery, poker
	CatAttribution = "attribution" // Install referrer, campaign, organic, SDK tracking
)

var (
	reURL       = regexp.MustCompile(`(?i)(https?|wss?|ftp)://`)
	reIPLiteral = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	reBase64    = regexp.MustCompile(`^[A-Za-z0-9+/=]{16,}$`)

	cryptoKeywords = []string{
		"encrypt", "decrypt", "cipher", "ciphertext",
		"xxtea", "xorcipher", "xordecrypt", "xorencrypt", "xorkey",
		"pbkdf", "argon2", "bcrypt", "scrypt",
		"digitalsignature", "verifysignature", "signingkey",
		"messagedigest",
		"hmacsha", "chacha", "blowfish", "twofish",
		"nonce", "saltvalue",
	}

	reCryptoShort = regexp.MustCompile(`(?i)(^|[^a-zA-Z])(aes|rsa|ecdsa|ecdh|hmac|sha1|sha256|sha512|md5|cbc|ecb|gcm|pkcs|xor|rc4|3des|salt|iv)([^a-zA-Z]|$)`)

	reAuth          = regexp.MustCompile(`(?i)(^|[^a-zA-Z])(oauth|jwt|bearer|credential|passwd|apikey|api_key|api-key|authorization|authenticate)([^a-zA-Z]|$)`)
	reAuthStandalone = regexp.MustCompile(`(?i)(^|[^a-z])(password|secret|login)([^a-z]|$)`)
	reAuthToken      = regexp.MustCompile(`(?i)(access.?token|auth.?token|refresh.?token|session.?token|user.?token|id.?token)`)

	netKeywords = []string{
		"httpclient", "httpwebrequest", "httppost", "httpget",
		"socketclient", "tcpclient", "udpclient",
		"dnsresolve", "dnslookup",
		"proxyserver", "httpproxy",
	}
	reNet = regexp.MustCompile(`(?i)(^|[^a-zA-Z])(socket|proxy|dns)([^a-zA-Z]|$)`)

	httpMethods = []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}

	signalExtensions = []string{
		".dex", ".so", ".apk", ".aab", ".ipa",
		".zip", ".tar", ".gz",
		".db", ".sqlite",
		".key", ".pem", ".cert", ".crt", ".p12", ".jks",
	}

	simKeywords = []string{
		"simcard", "checksim",
		"getimei", "readimei", "imeinumber", "fetchimei",
		"getimsi", "readimsi", "imsinumber",
		"telephonymanager", "subscriberid", "getline1number", "simoperator",
		"simcountry", "simserial",
	}
	reSIM = regexp.MustCompile(`(?i)(^|[^a-zA-Z])(imei|imsi|telephony)([^a-zA-Z]|$)`)

	smsKeywords = []string{
		"smslog", "sendsms", "readsms", "smsmanager",
	}
	reSMS = regexp.MustCompile(`(?i)(^|[^a-zA-Z])(sms|mms)([^a-zA-Z]|$)`)

	contactKeywords = []string{
		"contactlist", "addressbook", "calllog", "readcontacts",
		"contactaddress", "phonenumber",
	}

	locationKeywords = []string{
		"geolocation", "geofence", "latitude", "longitude",
		"currentlocation", "locationservice", "requestlocation",
		"enablelocation", "locationexception", "locationpermission",
		"lastknownlocation", "fusedlocation", "geopoint",
		"locationcallback", "locationlistener", "locationmanager",
		"locationrequest", "isenablelocation",
	}
	reLocationShort = regexp.MustCompile(`(?i)(^|[^a-zA-Z])(gps)([^a-zA-Z]|$)`)

	deviceInfoKeywords = []string{
		"deviceid", "androidid", "getdevice", "deviceinfo",
		"devicefingerprint", "devicemodel", "deviceattributes",
		"installreferrer", "installerstore",
		"packageinfo", "getpackageinfo", "packagename",
		"getinstalledpackages", "packagemanager",
		"applicationinfo", "getapplicationinfo",
	}

	cloakingKeywords = []string{
		"checkkeyword", "keywordcheck", "keywordmismatch",
		"isallowed", "checkandlaunch", "checkredirect",
		"cloak", "appcountry",
		"checklanguage", "checklocale", "checktimezone",
		"getdefaultlocale", "systemlocale", "devicelanguage",
		"timedelay", "scheduletask", "setinterval",
	}

	reDataCollect = regexp.MustCompile(`(?i)(data.?collect|mobile.?data|send.?all.?mobile|collect.?data|harvest|bulk.?data|scrape|exfiltrat)`)

	cameraKeywords = []string{
		"camerapermission", "cameraopen", "getavailablecameras",
		"takepicture", "recordvideo",
	}

	walletKeywords = []string{
		"mnemonic", "seedphrase", "bip39", "bip44", "bip32",
		"recoveryphrase", "backupphrase", "secretphrase",
		"wordlist", "passphrase", "derivepath",
		"hdwallet", "coldwallet", "hotwallet",
		"walletconnect", "walletaddress", "walletbalance",
		"walletprovider", "walletadapter",
		"blockchain", "smartcontract",
		"ethereum", "solana", "bitcoin", "binance",
		"polygonchain", "polygonnetwork",
		"tether", "usdc", "usdt",
		"erc20", "bep20", "trc20",
		"metamask", "trustwallet", "phantom", "coinbase",
		"uniswap", "pancakeswap", "opensea",
		"gasprice", "gaslimit", "gasfee",
		"nftmint", "nftmarket", "tokenuri", "tokenmeta",
	}
	reWallet = regexp.MustCompile(`(?i)(^|[^a-zA-Z])(wallet|mnemonic|seed.?phrase|web3|dapp|nft|defi|airdrop|bitcoin|ether|crypto.?currency|token.?transfer)([^a-zA-Z]|$)`)

	gamblingKeywords = []string{
		"casino", "slotmachine", "roulette", "blackjack",
		"jackpot", "spinwheel", "freespin",
		"sportsbet", "placebet", "betslip", "oddscalc",
		"bookmaker", "bookie", "handicap",
		"lottery", "lotto", "lucknumber", "lotterydraw",
		"pokerroom", "pokertable", "texasholdem",
		"placewager", "payout", "cashout",
		"topup", "recharge",
	}
	reGambling = regexp.MustCompile(`(?i)(^|[^a-zA-Z])(wager|casino|gamble|lottery|lotto|poker|roulette|jackpot)([^a-zA-Z]|$)`)

	attributionKeywords = []string{
		"installreferrer", "installattribution", "installsource",
		"googleplayinstallreferrer",
		"campaigndata", "campaignattribution", "campaigntracking",
		"conversiondata", "conversionvalue", "conversiontracking",
		"deferreddeeplink",
		"appsflyerlib", "appsflyerdata", "appsflyerconv",
		"branchmetrics", "branchuniversalobj",
		"kochavatracker", "kochavaevent",
		"singularsdk", "tenjinsdk", "airbridgesdk",
		"adjustattribution", "adjustsession", "adjustevent", "adjustconfig",
		"adjustdevice", "getadid",
	}
	reAttribution = regexp.MustCompile(`(?i)(^|[^a-zA-Z])(referrer|organic|campaign|attribution|appsflyer|kochava|utm_source|utm_medium|utm_campaign|utm_content|utm_term|install_referrer|ad_id|adid|gclid|fbclid)([^a-zA-Z]|$)`)

	webviewKeywords = []string{
		"loadurl", "loaddata", "loadrequest",
		"evaluatejavascript", "addjavascriptinterface",
		"javascriptchannel", "webviewclient", "webviewcontroller",
		"webchromeclient", "inappwebview", "inappbrowser",
		"shouldoverrideurlloading", "shouldinterceptrequest",
		"webmessagelistener", "onpagestarted", "onpagefinished",
		"customtab", "opencustomtab", "chrometab", "chromeclient",
		"startactivity", "intentfilter", "deeplink", "applink",
		"launchurl", "canlaunch", "urlscheme",
		"javabridge", "jsbridge", "nativebridge",
		"javascriptinterface", "postmessage",
		"cookiemanager", "setcookie", "getcookie", "clearcookie",
		"cookiejar", "cookiestore",
	}
	reWebView = regexp.MustCompile(`(?i)(^|[^a-zA-Z])(webview|loadurl|cookie|intent|jsbridge)([^a-zA-Z]|$)`)
)

// ClassifyString returns the set of signal categories matching the value.
// Returns nil if the string carries no signal.
func ClassifyString(value string) []string {
	if len(value) < 2 {
		return nil
	}

	var cats []string
	lower := strings.ToLower(value)

	if reURL.MatchString(value) && !isFrameworkURL(value) {
		cats = append(cats, CatURL)
	}

	if reIPLiteral.MatchString(value) && !isOID(value) {
		cats = append(cats, CatHost)
	}

	if containsKeyword(value, cryptoKeywords) || reCryptoShort.MatchString(value) {
		cats = append(cats, CatEncryption)
	}

	if reAuth.MatchString(value) || reAuthStandalone.MatchString(value) || reAuthToken.MatchString(value) {
		cats = append(cats, CatAuth)
	}

	for _, m := range httpMethods {
		if value == m {
			cats = append(cats, CatNet)
			break
		}
	}
	if !containsCat(cats, CatNet) {
		if containsKeyword(value, netKeywords) || reNet.MatchString(value) {
			cats = append(cats, CatNet)
		}
	}

	for _, ext := range signalExtensions {
		if strings.HasSuffix(lower, ext) || strings.Contains(lower, ext+" ") || strings.Contains(lower, ext+",") {
			cats = append(cats, CatFileExt)
			break
		}
	}

	trimmed := strings.TrimSpace(value)
	if reBase64.MatchString(trimmed) && entropy(value) > 3.5 && !isCamelCase(trimmed) && hasMixedCharClasses(trimmed) && !isPath(trimmed) {
		cats = append(cats, CatBase64Key)
	}

	if containsKeyword(value, simKeywords) || reSIM.MatchString(value) {
		cats = append(cats, CatSIM)
	}

	if containsKeyword(value, smsKeywords) || reSMS.MatchString(value) {
		cats = append(cats, CatSMS)
	}

	if containsKeyword(value, contactKeywords) {
		cats = append(cats, CatContacts)
	}

	if containsKeyword(value, locationKeywords) || reLocationShort.MatchString(value) {
		cats = append(cats, CatLocation)
	}

	if containsKeyword(value, deviceInfoKeywords) {
		cats = append(cats, CatDeviceInfo)
	}

	if containsKeyword(value, cloakingKeywords) {
		cats = append(cats, CatCloaking)
	}

	if reDataCollect.MatchString(value) {
		cats = append(cats, CatDataCollect)
	}

	if containsKeyword(value, cameraKeywords) {
		cats = append(cats, CatCamera)
	}

	if containsKeyword(value, webviewKeywords) || reWebView.MatchString(value) {
		cats = append(cats, CatWebView)
	}

	if (containsKeyword(value, walletKeywords) || reWallet.MatchString(value)) && !isDotNetAssemblyRef(value) {
		cats = append(cats, CatBlockchain)
	}

	if containsKeyword(value, gamblingKeywords) || reGambling.MatchString(value) {
		cats = append(cats, CatGambling)
	}

	if containsKeyword(value, attributionKeywords) || reAttribution.MatchString(value) {
		cats = append(cats, CatAttribution)
	}

	return cats
}

// IsMundaneRuntime returns true for IL2CPP runtime functions that represent
// codegen helpers, allocations, or type checks - noise in the signal graph.
func IsMundaneRuntime(name string) bool {
	lower := strings.ToLower(name)
	mundanePatterns := []string{
		"il2cpp_codegen_",
		"il2cpp_array_",
		"il2cpp_raise_",
		"il2cpp_runtime_",
		"il2cpp_vm_",
		"il2cpp_gc_",
		"il2cpp_object_new",
		"il2cpp_string_new",
		"il2cpp_type_get",
		"il2cpp_class_get",
		"il2cpp_field_get",
		"il2cpp_method_get",
		"il2cpp_resolve_",
		"box_", "unbox_",
		"castclass", "isinst",
		"write_barrier",
		"null_check",
		"array_bounds_check",
		"divide_by_zero_check",
		"mono_",
		"system.void",
		"system.object$$finalize",
		"system.object$$.ctor",
		"system.valuetype",
	}
	for _, p := range mundanePatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// frameworkNamespacePrefixes are standard library and engine namespaces whose
// functions should NOT be classified as signal from their names alone.
// They implement crypto, networking, etc. but are framework code, not app behavior.
var frameworkNamespacePrefixes = []string{
	"System.",
	"Mono.",
	"UnityEngine.",
	"Unity.",
	"Newtonsoft.",
	"Google.",
	"Microsoft.",
	"Bee.",

	// Common well-known third-party libraries.
	"DtdParserProxy",
	"ConnectionGroup",
	"AwaitableSocketAsyncEventArgs",
	"TaskSocketAsyncEventArgs",
}

// IsFrameworkNamespace returns true if the function name belongs to a
// standard library or engine namespace. Such functions are not signal
// from their names (though their string refs may still be signal).
func IsFrameworkNamespace(name string) bool {
	for _, p := range frameworkNamespacePrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// Severity levels for signal categories.
const (
	SeverityHigh   = "high"
	SeverityMedium = "medium"
	SeverityLow    = "low"
)

// CategorySeverity returns the severity level for a category.
func CategorySeverity(cat string) string {
	switch cat {
	case CatEncryption, CatAuth, CatSIM, CatSMS, CatContacts, CatCloaking, CatDataCollect, CatWebView, CatBlockchain, CatGambling:
		return SeverityHigh
	case CatURL, CatHost, CatBase64Key, CatLocation, CatDeviceInfo, CatCamera, CatAttribution:
		return SeverityMedium
	case CatNet, CatFileExt:
		return SeverityLow
	default:
		return SeverityLow
	}
}

// MaxSeverity returns the highest severity from a list of categories.
func MaxSeverity(categories []string) string {
	best := ""
	for _, c := range categories {
		s := CategorySeverity(c)
		if s == SeverityHigh {
			return SeverityHigh
		}
		if s == SeverityMedium {
			best = SeverityMedium
		} else if best == "" {
			best = SeverityLow
		}
	}
	if best == "" {
		return SeverityLow
	}
	return best
}

func isCamelCase(s string) bool {
	for i := 1; i < len(s); i++ {
		if s[i-1] >= 'a' && s[i-1] <= 'z' && s[i] >= 'A' && s[i] <= 'Z' {
			return true
		}
	}
	return false
}

func normalizeForMatch(s string) string {
	lower := strings.ToLower(s)
	var b strings.Builder
	b.Grow(len(lower))
	for i := 0; i < len(lower); i++ {
		c := lower[i]
		if c != '_' && c != '-' && c != ' ' && c != '.' {
			b.WriteByte(c)
		}
	}
	return b.String()
}

func containsKeyword(value string, keywords []string) bool {
	norm := normalizeForMatch(value)
	for _, kw := range keywords {
		if strings.Contains(norm, kw) {
			return true
		}
	}
	return false
}

func containsCat(cats []string, cat string) bool {
	for _, c := range cats {
		if c == cat {
			return true
		}
	}
	return false
}

// hasMixedCharClasses returns true if the string contains characters from
// at least two of: uppercase letters, lowercase letters, digits.
// Real base64 has mixed case + digits; all-lowercase strings are not base64.
func hasMixedCharClasses(s string) bool {
	var hasUpper, hasLower, hasDigit bool
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c >= 'a' && c <= 'z':
			hasLower = true
		case c >= '0' && c <= '9':
			hasDigit = true
		}
	}
	n := 0
	if hasUpper {
		n++
	}
	if hasLower {
		n++
	}
	if hasDigit {
		n++
	}
	return n >= 2
}

// isOID returns true if the string looks like an ASN.1 OID (e.g. "1.2.840.113549.1.1.1")
// rather than an IP address. OIDs have 4+ dots; IPv4 has exactly 3.
func isOID(s string) bool {
	dots := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			dots++
		}
	}
	return dots > 3
}

// isDotNetAssemblyRef returns true if the string looks like a .NET assembly reference
// containing PublicKeyToken=, Culture=, or Version= patterns.
// isDotNetAssemblyRef returns true if the string looks like a .NET assembly reference
// containing PublicKeyToken=, Culture=, or Version= patterns.
func isDotNetAssemblyRef(s string) bool {
	return strings.Contains(s, "PublicKeyToken=") || strings.Contains(s, "Culture=neutral")
}

// isPath returns true if the string looks like a file path (contains / without + or =).
func isPath(s string) bool {
	return strings.Contains(s, "/") && !strings.Contains(s, "+") && !strings.Contains(s, "=")
}

// isFrameworkURL returns true if the URL is a well-known framework/schema URL
// (W3C, XML schemas, Microsoft schemas) that is not interesting signal.
var frameworkURLPrefixes = []string{
	"http://www.w3.org/",
	"http://schemas.microsoft.com/",
	"http://schemas.xmlsoap.org/",
	"http://schemas.openxmlformats.org/",
	"http://james.newtonking.com/",
}

func isFrameworkURL(s string) bool {
	lower := strings.ToLower(s)
	for _, p := range frameworkURLPrefixes {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

func entropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[byte]int)
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	var ent float64
	for _, count := range freq {
		p := float64(count) / n
		if p > 0 {
			ent -= p * math.Log2(p)
		}
	}
	return ent
}
