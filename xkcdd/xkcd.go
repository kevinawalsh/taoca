// Copyright (c) 2015, Kevin Walsh.  All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"crypto/x509/pkix"
	"fmt"
	"net"
	"net/http"
	"path"
	"strconv"
	"strings"

	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/util/options"
	"github.com/kevinawalsh/taoca"
	"github.com/kevinawalsh/taoca/https"
)

var name = &pkix.Name{
	Country:            []string{"US"},
	Province:           []string{"MA"},
	Locality:           []string{"Oakham"},
	Organization:       []string{"Google"},
	OrganizationalUnit: []string{"CloudProxy Password Generator"},
	CommonName:         "",
}

var opts = []options.Option{
	// Flags for all commands
	{"host", "0.0.0.0", "<address>", "Address for listening", "all,persistent"},
	{"port", "8444", "<port>", "Port for listening", "all,persistent"},
	{"init", false, "", "Initialize fresh https keys and certificate", "all"},
	{"keys", "", "<dir>", "Directory for storing keys and associated certificates", "all,persistent"},
	{"config", "/etc/tao/xkcd/xkcd.config", "<file>", "Location for storing configuration", "all"},
}

func init() {
	options.Add(opts...)
}

func main() {
	options.Parse()
	if *options.String["config"] != "" && !*options.Bool["init"] {
		err := options.Load(*options.String["config"])
		options.FailIf(err, "Can't load configuration")
	}

	fmt.Println("Cloudproxy XKCD HTTPS Password Generator")

	if tao.Parent() == nil {
		options.Fail(nil, "can't continue: no host Tao available")
	}

	// TODO(kwalsh) extend tao name with operating mode and policy

	addr := net.JoinHostPort(*options.String["host"], *options.String["port"])

	cpath := *options.String["config"]
	kdir := *options.String["keys"]
	if kdir == "" && cpath != "" {
		kdir = path.Dir(cpath)
	} else if kdir == "" {
		options.Fail(nil, "Option -keys or -config is required")
	}

	var keys *tao.Keys

	if *options.Bool["init"] {
		keys = taoca.GenerateKeys(name, addr, kdir)
	} else {
		keys = taoca.LoadKeys(kdir)
	}

	fmt.Printf("Configuration file: %s\n", cpath)
	if *options.Bool["init"] && cpath != "" {
		err := options.Save(cpath, "XKCD HTTPS password generator configuration", "persistent")
		options.FailIf(err, "Can't save configuration")
	}

	http.Handle("/cert/", https.CertificateHandler{keys.CertificatePool})
	http.Handle("/index.html", http.RedirectHandler("/", 301))
	http.HandleFunc("/", pwgen)
	fmt.Printf("Listening at %s using HTTPS\n", addr)
	err := tao.ListenAndServeTLS(addr, keys)
	options.FailIf(err, "can't listen and serve")

	fmt.Println("Server Done")
}

func pwgen(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	a, ok := q["n"]
	if !ok || len(a) == 0 {
		a = []string{"6"}
	}
	n, err := strconv.Atoi(a[0])
	if err != nil {
		n = 6
	}
	if n < 2 {
		n = 2
	} else if n > 8 {
		n = 8
	}
	comment := PasswordLengthComments[n]
	w.Header().Set("Content-Type", "text/html")
	pw1, pw2, pw3, err := Password(n)
	if err != nil {
		comment = fmt.Sprintf("error: %s", err)
	}
	body := fmt.Sprintf(html, n, comment, pw1, pw2, pw3)
	w.Write([]byte(body))
}

var html = `<html><head><title>Cloudproxy xkcd Password Generator</title></head>
<style>
b { color: #aa0000; font-weight: bold; font-style: normal; }
i { color: #00aa00; font-weight: bold; font-style: normal; }
span { color: #880088; font-weight: bold; font-style: normal; font-size: large; }
div { border: 1px solid black; width: 600px; margin: 0 50px; padding: 30px; }
</style>
<body>
<p>The button below will generate a random password that is easy to remember, but hard for even a computer to guess.</p>
<div>
<form action="/" method="get">
<p>Weak <input type="range" name="n" min="2" max="8" value="%d" onchange="this.form.submit()" /> Strong</p>
<p>%s</p>
<p><input type="submit" value="Generate Another!"/></p>
</form>

<p>Your password: <span>%s</span></p>
<p>Alternative password 1: <span>%s</span>
   (for sites with pointless password restrictions)</p>
<p>Alternative password 2: <span>%s</span>
   (for sites with even more password restrictions)</p>
</div>

<p>This page and the password generator algorithm is based on code by
  <a href="http://preshing.com/20110811/xkcd-password-generator/">Jeff Preshing</a>,
  who was inspired by <a href="http://xkcd.com/936/">this xkcd strip</a> to
  create this password generator. This is essentially a software-version of
  <a href="http://world.std.com/~reinhold/diceware.page.html">diceware</a>.</p>

<p>All computations are done on a Cloudproxy HTTPs server, but the server does
not record or leak this password. Promise! In order to gain some assurance that
we aren't lying to you, you can do the following:
<ol>
  <li>Make sure you are accessing this site over a private <b>HTTPS
      connection</b>. This ensures you are really connecting with the
	  server holding some private key.</li>
  <li>Examine the HTTPS <b>x509 certificate</b> (e.g. click the lock, go to
	  <i>Connection</i>, then <i>Certificate Details</i>). Make sure it was
	  issued by a CloudProxy Certificate Authority (CA) that you trust. In
	  particular, you need to trust the CA to maintain the secrecy of its
	  private key and to only issue certificates that link to an accurate
	  representation of the practices and policies under which it approves
	  certificate signing requests.</li>
  <li>Next find the <b>Certificate Policies</b> within the x509 certificate
      (e.g. click <i>Details</i>). There you should find two URLs, the first linking
      to a <i>certification Practices Statement</i>, the second to a <i>User
      Notice</i>. Download these files (the links will point <a href="/security/">here</a>).</li>
  <li><b>Compute the sha256 hash of each file</b> and check that it matches the
	  hash in the corresponding URL. This step ensures the files haven't been
	  tampered with after they were generated by the certificate authority.
	  Since you trusted the CA in the previous step, you can now have some
	  assurance that you are looking at the actual policies under which your
	  trusted CA is running.</li>
  <li>Next, <b>examine the policy file contents</b>. Together, they give
	  details about this server's software and hardware. Mostly it is just a few
	  hashes and public keys, so you will need to check that the hash matches
	  the hash of software you trust and/or check to make sure the public key
	  corresponds to some entity you trust.</li>
  <li>You can now <b>decide if you trust that software and hardware</b> to properly
      implement https, protect the secrecy of the private https key, properly
      generate a random password, not record or leak the password, etc.</li>
</ol>

</body></html>`

// Password generates a new set of passwords with n words or equivalent.
func Password(n int) (string, string, string, error) {
	b, err := tao.Parent().GetRandomBytes(n * 2)
	if err != nil {
		return "", "", "", err
	}
	var words []string
	var alt1 []byte
	var alt2 []byte
	for i := 0; i < n; i++ {
		r0 := int(b[2*i])
		r1 := int(b[2*i+1])
		var r = int(r1*256+r0) % len(Wordlist)
		words = append(words, Wordlist[r%len(Wordlist)])
		alt1 = append(alt1, SmallAlphabet[r0%len(SmallAlphabet)])
		alt1 = append(alt1, SmallAlphabet[r1%len(SmallAlphabet)])
		alt2 = append(alt2, TinyAlphabet[r0%len(TinyAlphabet)])
		alt2 = append(alt2, TinyAlphabet[r1%len(TinyAlphabet)])
	}
	return strings.Join(words, " "), string(alt1), string(alt2), nil
}

// Code below was adapted and ported to Go by Kevin Walsh <kwalsh@cs.holycross.edu> from code
// by Jeff Preshing. The original license was as follows.
//
//-------------------------------------------------------------------
// Copyright (c) 2011, Jeff Preshing
// http://preshing.com/20110811/xkcd-password-generator
// All rights reserved.
//
// Some parts based on http://www.mytsoftware.com/dailyproject/PassGen/entropy.js, copyright 2003 David Finch.
//
// Released under the Modified BSD License:
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//     * Neither the name of the <organization> nor the
//       names of its contributors may be used to endorse or promote products
//       derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//-------------------------------------------------------------------

var PasswordLengthComments = map[int]string{
	2: "       Two random words is a <b>very weak</b> password (24 bits, or about 1 in 16 million). This will keep out your little brother.",
	3: "   Three random words is a <b>fairly weak</b> password (36 bits, or about 1 in 68 billion). This will keep out your clever dad.",
	4: "  Four random words is a <b>somewhat weak</b> password (48 bits, or about 1 in 280 trillion). This will keep out only casual attackers.",
	5: "Five random words is a <i>somewhat strong</i> password (60 bits, or about 1 in 1 billion billion). Probably sufficient for non-critical data.",
	6: " Six random words is a <i>decently strong</i> password (72 bits, or about 1 in 4 billion trillion). Probably sufficient to protect most data.",
	7: "  Seven random words is a <i>quite strong</i> password (84 bits, or about 1 in 19 trillion trillion). Probably sufficient to keep out most casual attackers.",
	8: "   Eight random words is a <i>very strong</i> password (96 bits, or about 1 in 79 thousand trillion trillion). Above this level, you should not be using this web site.",
}

// A list of words to choose from. The list must be:
// (a) Sufficiently long. This list has over 4096 words, which consumes a tad
//     more than 12 bits of entropy per word choice.
// (b) Does not contain duplicates.
// (c) Doesn't contain words that are too obscure, hard to remember, difficult
//     to spell, or have multiple common spellings or homonyms. Because I edited
//     this list by hand, some less-than-ideal word choices have slipped
//     through.
// (d) Does not contain very short words (e.g. less than 4 characters).
// Other than the above properties, the actual contents of the list is pretty
// much irrelevant. It doesn't even need to be kept secret. You could equally
// well replace this list with a list of your 2048 favorite foods, or places, or
// characters from books, etc.
//
// Some of this list was scraped by Jeff Preshing from a list of common english
// words in newspapers
// (http://www.paulnoll.com/Books/Clear-English/English-3000-common-words.html).
// Additional words were taken from the diceware list, but only those that appear
// in a dictionary and are at least 4 characters long
// (http://world.std.com/~reinhold/diceware.wordlist.asc).
// Additional words were hand selected by Kevin Walsh from a Harry Potter
// lexicon (http://www.hp-lexicon.org/).
var Wordlist = [...]string{
	"aback", "abase", "abash", "abate", "abbey", "abbot", "abed", "abet", "abide",
	"ability", "abject", "ablaze", "able", "aboard", "abode", "abominable",
	"abort", "about", "above", "abrade", "absorb", "abuse", "abut", "abyss",
	"academics", "academy", "accept", "accident", "accio", "according", "account",
	"accrue", "accurate", "acetic", "ache", "acid", "acidic", "acme", "acorn",
	"acre", "acres", "acrid", "across", "action", "active", "activity", "actor",
	"acts", "actual", "actually", "acuity", "acute", "adage", "adagio", "adapt",
	"added", "addict", "addition", "additional", "addle", "adept", "adieu",
	"adjective", "adjust", "admit", "adobe", "adopt", "adore", "adorn", "adult",
	"advance", "advent", "adventure", "advert", "advice", "advise", "aegis",
	"afar", "affair", "affect", "affix", "afire", "afoot", "afraid", "africa",
	"after", "afternoon", "again", "against", "agate", "agave", "agenda", "agent",
	"agents", "agile", "aging", "agony", "agree", "ague", "ahead", "ahem", "ahoy",
	"aide", "aides", "ain't", "airman", "airplane", "airway", "airy", "aisle",
	"ajar", "akin", "alarm", "albania", "albino", "album", "albus", "alchemy",
	"alder", "alert", "alfred", "alga", "algae", "alias", "alibi", "alien",
	"alight", "align", "alike", "alive", "allay", "alley", "allied", "allot",
	"allow", "alloy", "allure", "ally", "almond", "almost", "aloe", "aloft",
	"aloha", "alone", "along", "aloof", "aloud", "alpha", "alphabet", "already",
	"also", "altar", "alter", "although", "alto", "alum", "alumni", "always",
	"amass", "amaze", "amber", "amble", "ambush", "amen", "amend", "amid",
	"amigo", "amiss", "amity", "ammo", "amok", "among", "amount", "ampere",
	"ample", "amply", "amulet", "amulets", "amuse", "analysis", "ancient",
	"andromeda", "anew", "angel", "anger", "angle", "angry", "angst", "animal",
	"animals", "anion", "anise", "ankle", "annex", "announced", "annoy", "annul",
	"anode", "another", "answer", "ante", "anthology", "anti", "antic",
	"antidote", "antigone", "antler", "ants", "anus", "anvil", "anybody",
	"anyhow", "anyone", "anything", "anyway", "anywhere", "aorta", "apart",
	"apartment", "apathy", "apex", "aphid", "aplomb", "apparate", "appeal",
	"appearance", "append", "apple", "applied", "apply", "appropriate", "apron",
	"apse", "aqua", "arch", "archer", "archive", "ardent", "area", "arena",
	"ares", "argon", "argot", "argue", "arid", "arise", "armadillo", "armenia",
	"army", "aroma", "arose", "around", "arrange", "arrangement", "array",
	"arrival", "arrive", "arrow", "arson", "artery", "article", "artifact",
	"artists", "artwork", "arty", "ascend", "ashen", "ashy", "aside", "askew",
	"asleep", "aspen", "aspire", "assay", "asset", "assistant", "assort",
	"assure", "aster", "astral", "astronomy", "atlantic", "atlas", "atmosphere",
	"atom", "atomic", "atone", "atop", "attached", "attack", "attempt",
	"attention", "attic", "attire", "audience", "audio", "audit", "auger",
	"augur", "august", "aunt", "aura", "aural", "author", "auto", "automobile",
	"autumn", "avail", "available", "aver", "average", "avert", "avid", "avoid",
	"avow", "await", "awake", "award", "aware", "awash", "away", "awful", "awoke",
	"awry", "axes", "axial", "axiom", "axis", "axle", "axon", "azure", "babble",
	"babe", "babel", "baby", "back", "backup", "bacon", "bade", "badge", "badly",
	"baffle", "baggy", "bail", "bait", "bake", "baking", "balance", "bald",
	"bale", "balk", "balky", "ball", "balled", "balloon", "ballot", "balm",
	"balmy", "balsa", "banal", "band", "bandit", "bandy", "bane", "bang",
	"banish", "banjo", "bank", "banks", "barb", "bard", "bare", "barge", "bark",
	"barking", "barley", "barn", "baron", "barter", "basal", "base", "baseball",
	"bash", "basic", "basil", "basin", "basis", "bask", "basket", "bass", "bassi",
	"basso", "baste", "batch", "bate", "bates", "bath", "bathe", "bathroom",
	"batik", "baton", "battle", "bauble", "baud", "bawdy", "bawl", "bayed",
	"bayou", "bazaar", "beach", "bead", "beady", "beak", "beam", "bean", "beans",
	"bear", "beard", "beast", "beat", "beater", "beau", "beautiful", "beauty",
	"beaux", "bebop", "becalm", "became", "because", "beck", "become", "becoming",
	"beech", "beef", "beefy", "been", "beep", "beer", "beet", "beetle", "befall",
	"befit", "befog", "before", "began", "beget", "beggar", "begin", "beginning",
	"begun", "behavior", "behind", "beige", "being", "belch", "belfry", "belie",
	"believed", "bell", "belle", "belly", "belong", "below", "belt", "bemoan",
	"bench", "bend", "bender", "beneath", "bent", "bereft", "beret", "berg",
	"berry", "berth", "beryl", "beset", "beside", "best", "bestir", "beta",
	"betray", "better", "between", "bevel", "bevy", "beware", "bewitch", "beyond",
	"bias", "bible", "bicep", "biceps", "bicycle", "biddy", "bide", "bigfoot",
	"bigger", "biggest", "bighead", "bigot", "bile", "bilge", "bilk", "bill",
	"billow", "billy", "binary", "bind", "binge", "binky", "birch", "bird",
	"birdie", "birds", "birth", "birthday", "bishop", "bison", "bisque", "bitch",
	"bite", "bitten", "blab", "black", "blade", "blame", "bland", "blank",
	"blanket", "blare", "blast", "blasting", "blaze", "bleak", "bleat", "bled",
	"bleed", "blend", "bless", "blest", "blew", "blimp", "blind", "blink", "blip",
	"bliss", "blithe", "blitz", "bloat", "blob", "bloc", "block", "blond",
	"blonde", "blood", "bloodhound", "bloom", "blot", "blotch", "blotts", "blow",
	"blown", "blue", "bluebell", "bluff", "blunt", "blur", "blurt", "blush",
	"boar", "board", "boast", "boat", "boats", "bobbin", "bobby", "bobcat",
	"bode", "body", "bogey", "boggy", "bogus", "bogy", "boil", "bold", "bole",
	"bolt", "bomb", "bond", "bone", "bones", "bonfire", "bong", "bongo", "bonus",
	"bony", "booby", "boogie", "book", "bookbag", "bookcase", "books", "bookshop",
	"boom", "boon", "boor", "boost", "boot", "booth", "boots", "booty", "booze",
	"borax", "border", "bore", "born", "borne", "boron", "bosom", "boss", "botch",
	"both", "bottle", "bottles", "bottom", "bough", "bouncy", "bound", "bout",
	"bovine", "bowel", "bowl", "boxing", "brace", "bract", "brad", "brag",
	"braid", "brain", "brains", "brainy", "brake", "bran", "branch", "brand",
	"brash", "brass", "brassy", "brave", "bravo", "brawl", "bray", "bread",
	"break", "breakfast", "breath", "breathe", "breathing", "bred", "breed",
	"breeze", "brew", "briar", "bribe", "brick", "bride", "bridge", "brief",
	"brig", "bright", "brim", "brine", "bring", "brink", "briny", "brisk",
	"broad", "broil", "broke", "broken", "brood", "brook", "broom", "broth",
	"brother", "brought", "brow", "brown", "browse", "brunch", "brunt", "brush",
	"brute", "buck", "buddy", "budge", "buff", "buffalo", "buggy", "bugle",
	"build", "building", "built", "bulb", "bulge", "bulk", "bulky", "bull",
	"bully", "bump", "bunch", "bunk", "bunny", "bunt", "buoy", "bureau", "burg",
	"buried", "burly", "burn", "burnt", "burp", "burr", "burro", "burst", "bury",
	"bush", "bushel", "bushy", "business", "buss", "bust", "busy", "butane",
	"butch", "butt", "butte", "butter", "buxom", "buyer", "buzz", "buzzer",
	"bylaw", "byline", "byte", "byway", "byword", "cabal", "cabin", "cable",
	"cacao", "cache", "cacti", "caddy", "cadet", "cadre", "cage", "cagey",
	"cairn", "cake", "cakes", "calf", "call", "callus", "calm", "calve", "camber",
	"came", "camel", "cameo", "camera", "camp", "canada", "canal", "canary",
	"cancer", "candle", "candy", "cane", "cannot", "canny", "canoe", "canon",
	"canopy", "cant", "can't", "canto", "canton", "cape", "caper", "capital",
	"captain", "capture", "captured", "carbon", "card", "care", "careful",
	"carefully", "caress", "caret", "cargo", "carol", "carp", "carpet", "carried",
	"carry", "cart", "carve", "case", "cash", "cashew", "cask", "casket", "cast",
	"caste", "castle", "catch", "catchers", "cater", "cathedral", "catkin",
	"catsup", "cattle", "caught", "cauldron", "caulk", "cause", "cave", "cavern",
	"cavil", "cavort", "cease", "cedar", "cede", "cell", "census", "cent",
	"centaur", "center", "central", "century", "certain", "certainly", "chafe",
	"chaff", "chain", "chains", "chair", "chalk", "chamber", "champ", "chance",
	"change", "changing", "chant", "chaos", "chap", "chapel", "chapter", "char",
	"character", "characteristic", "charge", "charity", "charm", "charmed",
	"chart", "chase", "chasm", "chaste", "chat", "cheap", "cheat", "cheating",
	"check", "cheek", "cheeky", "cheer", "cheese", "chef", "chemical", "cherry",
	"cherub", "chess", "chest", "chew", "chic", "chick", "chicken", "chide",
	"chief", "child", "children", "chile", "chili", "chill", "chilly", "chime",
	"chin", "china", "chink", "chip", "chirp", "chisel", "chit", "chive", "chock",
	"choice", "choir", "choke", "chomp", "choose", "chop", "choral", "chord",
	"chore", "chose", "chosen", "chow", "chuck", "chug", "chum", "chump", "chunk",
	"church", "churn", "chute", "cicada", "cider", "cigar", "cilia", "cinch",
	"cipher", "circa", "circle", "circus", "cite", "citizen", "citrus", "city",
	"civet", "civic", "civil", "clad", "claim", "clam", "clammy", "clamp", "clan",
	"clang", "clank", "clap", "clash", "clasp", "class", "classroom", "clause",
	"claw", "claws", "clay", "clean", "clear", "clearly", "cleat", "cleft",
	"clerk", "click", "cliff", "climate", "climb", "clime", "cling", "clink",
	"clip", "cloak", "clock", "clod", "clog", "clomp", "clone", "close",
	"closely", "closer", "closet", "clot", "cloth", "clothes", "clothing",
	"cloud", "clout", "clove", "clown", "cloy", "club", "cluck", "clue", "clump",
	"clumsy", "clung", "coach", "coal", "coast", "coat", "coax", "cobble",
	"cobra", "cock", "cockle", "cocky", "cocoa", "coda", "coddle", "code", "coed",
	"coffee", "cogent", "coil", "coin", "coke", "cola", "cold", "collect",
	"college", "colon", "colony", "color", "colt", "column", "coma", "comb",
	"combat", "combination", "combine", "come", "comet", "comfortable", "comic",
	"coming", "comma", "command", "common", "community", "company", "compare",
	"compass", "complete", "completely", "complex", "composed", "composition",
	"compound", "concerned", "conch", "condition", "cone", "congress", "conic",
	"conjure", "connected", "consider", "consist", "consonant", "conspire",
	"constantly", "construction", "contain", "continent", "continued", "contrast",
	"control", "conversation", "cook", "cookies", "cooky", "cool", "coon", "coop",
	"coot", "cope", "copper", "copra", "copy", "coral", "cord", "core", "cork",
	"corn", "corner", "corny", "corps", "correct", "correctly", "cost", "costume",
	"cosy", "cottage", "cotton", "couch", "cough", "could", "council", "count",
	"country", "coup", "coupe", "couple", "courage", "course", "court", "cousin",
	"cove", "coven", "cover", "covet", "cowboy", "cowl", "coyote", "cozen",
	"cozy", "crab", "crack", "cracker", "craft", "crag", "cram", "cramp", "crane",
	"crank", "crap", "crash", "crass", "crate", "crater", "crave", "craw",
	"crawl", "craze", "crazy", "creak", "cream", "create", "creature", "credit",
	"credo", "creed", "creek", "creep", "creole", "crepe", "crept", "crescent",
	"cress", "crest", "crew", "crib", "cried", "crime", "crimp", "crisp", "croak",
	"crock", "crocus", "crone", "crony", "crook", "croon", "crop", "cross",
	"crow", "crowd", "crown", "crud", "crude", "cruel", "crumb", "crush", "crust",
	"crux", "crypt", "crystal", "cube", "cubic", "cuddle", "cuff", "cull", "cult",
	"cumin", "cupful", "curb", "curd", "cure", "curfew", "curie", "curio",
	"curious", "curl", "current", "curry", "curse", "curt", "curve", "cusp",
	"customs", "cute", "cutlet", "cutting", "cycle", "cynic", "cyst", "czar",
	"dactyl", "daddy", "daffy", "dahlia", "daily", "dairy", "dais", "daisy",
	"dale", "dally", "damage", "dame", "damn", "damp", "damsel", "dance", "dandy",
	"danger", "dangerous", "dank", "dare", "dark", "darken", "darkness", "darn",
	"dart", "dash", "data", "date", "datum", "daub", "daughter", "daunt", "davit",
	"dawn", "daze", "dazzle", "deacon", "dead", "deaf", "deal", "dealt", "dean",
	"dear", "death", "debar", "debit", "debris", "debt", "debug", "debut",
	"decal", "decay", "decide", "deck", "declared", "decor", "decree", "decry",
	"deed", "deem", "deep", "deeply", "deer", "defeat", "defence", "defer",
	"definition", "deform", "deft", "defy", "degree", "deify", "deign", "deity",
	"delay", "dell", "delta", "delve", "dementor", "demon", "demur", "denial",
	"dense", "dent", "deny", "depend", "depot", "depth", "depute", "derby",
	"describe", "desert", "design", "desist", "desk", "destiny", "detach",
	"detail", "deter", "determine", "deuce", "develop", "development", "device",
	"devil", "devoid", "dewy", "diagram", "dial", "diameter", "diary", "dibble",
	"dice", "dick", "dicta", "died", "diesel", "diet", "differ", "difference",
	"different", "difficult", "difficulty", "digit", "dilate", "dill", "dime",
	"dine", "ding", "dingbat", "dingo", "dingy", "dinner", "dint", "diode",
	"dire", "direct", "direction", "directly", "dirge", "dirt", "dirty",
	"disappear", "disc", "discover", "discovery", "discuss", "discussion",
	"disease", "dish", "disk", "distance", "distant", "ditch", "ditto", "ditty",
	"diva", "divan", "dive", "divide", "division", "dizzy", "dock", "docket",
	"doctor", "dodge", "dodo", "does", "doff", "dogma", "doing", "dole", "doll",
	"dollar", "dolly", "dolt", "dome", "done", "donkey", "donor", "don't", "doom",
	"door", "dope", "dose", "dote", "double", "doubt", "dough", "dour", "douse",
	"dove", "dowel", "down", "downfall", "downs", "dowry", "doze", "dozen",
	"drab", "draft", "drag", "dragon", "drain", "drake", "dram", "drama", "drank",
	"drape", "draw", "drawl", "drawn", "dread", "dream", "dreamy", "dress",
	"dressy", "drew", "dried", "drier", "drift", "drill", "drink", "drip",
	"drive", "driven", "driver", "driving", "droll", "drone", "drool", "droop",
	"drop", "dropped", "dross", "drove", "drown", "drub", "drug", "druid", "drum",
	"drunk", "dryad", "dual", "ducat", "duck", "duct", "duel", "duet", "duff",
	"duke", "dull", "dully", "duly", "dumb", "dummy", "dump", "dumpy", "dunce",
	"dune", "dung", "dungeon", "dunk", "dupe", "during", "dusk", "dusky", "dust",
	"dusty", "duty", "dwarf", "dwell", "dwelt", "dyer", "dying", "dyke", "each",
	"eager", "eagle", "earl", "earlier", "early", "earn", "earth", "ease",
	"easel", "easier", "easily", "east", "easy", "eaten", "eater", "eating",
	"eave", "ebony", "echo", "eddy", "edge", "edgy", "edict", "edify", "edit",
	"editor", "education", "e'er", "eerie", "efface", "effect", "effort",
	"egress", "egret", "egypt", "eider", "eight", "either", "eject", "elate",
	"elbow", "elder", "elect", "electric", "electricity", "elegy", "element",
	"elephant", "eleven", "elfin", "elide", "elite", "elope", "else", "elude",
	"elves", "embalm", "embark", "embed", "ember", "emcee", "emery", "emit",
	"empire", "empty", "enact", "enamel", "enchant", "enchantment", "endow",
	"enemy", "energy", "engine", "engineer", "engulf", "enjoy", "enmity",
	"enough", "ensue", "enter", "entire", "entirely", "entrail", "entrap",
	"entry", "environment", "envoy", "envy", "epic", "epoch", "epoxy", "equal",
	"equally", "equator", "equip", "equipment", "erase", "erect", "erode",
	"errand", "error", "erupt", "escape", "especially", "essay", "essential",
	"establish", "ester", "etch", "ether", "ethic", "ethics", "ethos", "eureka",
	"evade", "even", "evening", "event", "eventually", "ever", "every",
	"everybody", "everyone", "everything", "everywhere", "evict", "evidence",
	"evil", "evoke", "evolution", "evolve", "exact", "exactly", "exalt", "exam",
	"examine", "example", "excel", "excellent", "except", "excess", "exchange",
	"excited", "excitement", "exciting", "exclaimed", "exercise", "exert",
	"exile", "exist", "exit", "exodus", "expect", "expel", "experience",
	"experiment", "explain", "explanation", "explore", "express", "expression",
	"extant", "extent", "extol", "extra", "extras", "exude", "exult", "eyed",
	"fable", "fabulous", "face", "facet", "facile", "facing", "fact", "factor",
	"factory", "facts", "fade", "fail", "failed", "fain", "faint", "fair",
	"fairly", "fairy", "faith", "fake", "fall", "fallen", "false", "fame",
	"familiar", "family", "famous", "fancy", "fang", "fangs", "fanny", "fantasy",
	"farce", "fare", "farm", "farmer", "farther", "fast", "fastened", "faster",
	"fatal", "fate", "father", "fatty", "fault", "faun", "fauna", "favorite",
	"fawn", "faze", "fear", "fearless", "feast", "feat", "feather", "feathers",
	"feature", "feed", "feel", "feet", "feign", "feint", "fell", "fellow",
	"felon", "felt", "femur", "fence", "fend", "fern", "ferric", "ferry", "fest",
	"fetal", "fetch", "fetid", "fetus", "feud", "fever", "fewer", "fiat", "fiche",
	"fief", "field", "fiend", "fierce", "fiery", "fife", "fifteen", "fifth",
	"fifty", "fight", "fighting", "figure", "filch", "file", "filet", "fill",
	"filler", "filly", "film", "filmy", "filth", "final", "finale", "finally",
	"finch", "find", "fine", "finest", "finger", "finish", "finite", "fink",
	"finny", "fire", "fireball", "fireplace", "firm", "first", "fish", "fishy",
	"fist", "five", "fixing", "fjord", "flack", "flag", "flail", "flair", "flak",
	"flake", "flaky", "flame", "flank", "flap", "flare", "flash", "flask", "flat",
	"flavor", "flaw", "flax", "flea", "fleck", "fled", "flee", "fleet", "flesh",
	"flew", "flex", "flick", "flier", "flies", "flight", "flinch", "fling",
	"flint", "flip", "flirt", "flit", "float", "floating", "flock", "floe",
	"flog", "flood", "floor", "flop", "floppy", "flora", "flour", "flout", "flow",
	"flower", "flowers", "flown", "flub", "flue", "fluff", "fluffy", "fluid",
	"fluke", "flung", "flush", "flute", "flux", "flyer", "foal", "foam", "foamy",
	"focal", "foci", "focus", "fodder", "foggy", "fogy", "foil", "foist", "fold",
	"folio", "folk", "folks", "follow", "folly", "fond", "font", "food", "fool",
	"foot", "football", "foray", "force", "ford", "fore", "foreign", "forest",
	"forge", "forget", "forgot", "forgotten", "fork", "form", "former", "forms",
	"fort", "forte", "forth", "forty", "forum", "forward", "fossil", "fought",
	"foul", "found", "founding", "fount", "fountain", "four", "fourth", "fowl",
	"foxy", "foyer", "frail", "frame", "franc", "frank", "fraud", "fray", "freak",
	"free", "freed", "freedom", "freer", "frenzy", "frequently", "fresh", "fret",
	"friar", "fried", "friend", "friendly", "frighten", "frill", "frilly",
	"fringe", "frisky", "frock", "frog", "frogs", "from", "front", "frost",
	"frosty", "froth", "frown", "froze", "frozen", "fruit", "fruitbat", "fudge",
	"fuel", "fugue", "full", "fully", "fume", "function", "fund", "fungal",
	"fungi", "funk", "funny", "furball", "furl", "furniture", "furry", "further",
	"fury", "furze", "fuse", "fuss", "fussy", "fusty", "future", "fuzz", "fuzzy",
	"gable", "gadget", "gaff", "gaffe", "gage", "gain", "gait", "gala", "galaxy",
	"gale", "gall", "galleon", "gallery", "gallop", "game", "games", "gamin",
	"gamma", "gamut", "gander", "gang", "gape", "garage", "garb", "garden",
	"garish", "garner", "gash", "gasoline", "gasp", "gassy", "gate", "gates",
	"gather", "gauche", "gaudy", "gauge", "gaunt", "gauze", "gave", "gavel",
	"gawk", "gawky", "gaze", "gear", "gecko", "geese", "geld", "gene", "general",
	"generally", "genie", "genii", "genre", "gent", "gentle", "gently", "gentry",
	"genus", "gerbil", "germ", "getting", "ghetto", "ghost", "ghoul", "giant",
	"giants", "gibe", "giddy", "gift", "gild", "gill", "gilt", "gimpy", "ginger",
	"gird", "girl", "girth", "gist", "give", "given", "giving", "glad", "glade",
	"glamor", "gland", "glare", "glass", "glaze", "gleam", "glean", "glee",
	"glen", "glib", "glide", "glint", "gloat", "glob", "globe", "gloom", "gloomy",
	"glory", "gloss", "glove", "gloves", "glow", "glue", "glued", "gluey",
	"gluing", "glum", "glut", "glyph", "gnarl", "gnash", "gnat", "gnaw", "gnome",
	"goad", "goal", "goat", "goblet", "goblin", "goes", "goggle", "gold",
	"golden", "golf", "golly", "gone", "gong", "good", "goods", "goody", "goof",
	"goofy", "goose", "gore", "gorge", "gorse", "gory", "gosh", "gospel", "gouge",
	"gourd", "gout", "government", "gown", "grab", "grabbed", "grace", "grad",
	"grade", "gradually", "graft", "grail", "grain", "grand", "grandfather",
	"grandmother", "grant", "grape", "graph", "graphic", "grasp", "grass",
	"grate", "grater", "grave", "gravity", "gravy", "gray", "graze", "great",
	"greater", "greatest", "greatly", "grebe", "greed", "greedy", "green",
	"greet", "grew", "grey", "grid", "grief", "grieve", "grill", "grim", "grime",
	"grin", "grind", "grip", "gripe", "grist", "grit", "groan", "groin", "groom",
	"grope", "gross", "ground", "group", "grout", "grove", "grow", "growl",
	"grown", "growth", "grub", "gruff", "grunt", "guano", "guard", "guess",
	"guest", "guide", "guild", "guile", "guilt", "guise", "guitar", "gulf",
	"gull", "gully", "gulp", "gumbo", "gummy", "gunk", "gunny", "gurgle", "guru",
	"gush", "gust", "gusto", "gusty", "gutsy", "gypsy", "gyro", "habit", "hack",
	"haiku", "hail", "hair", "hairy", "hale", "half", "halfway", "hall", "halo",
	"halt", "halve", "hand", "handbook", "handle", "handsome", "handy", "hang",
	"hank", "happen", "happened", "happily", "happy", "harbor", "hard", "harder",
	"hardly", "hardy", "hare", "harem", "hark", "harm", "harp", "harpy", "harry",
	"harsh", "hart", "hash", "hasp", "haste", "hasty", "hatch", "hate", "hater",
	"hath", "hatred", "haul", "haunt", "have", "haven", "having", "havoc", "hawk",
	"hays", "hazard", "haze", "hazel", "hazy", "head", "headed", "heading",
	"headlamp", "headless", "heady", "heal", "healer", "health", "heap", "hear",
	"heard", "hearing", "heart", "heat", "heath", "heave", "heavy", "heck",
	"heckle", "he'd", "hedge", "heed", "heel", "heft", "hefty", "height", "heir",
	"held", "helix", "hell", "he'll", "hello", "helm", "help", "helpful", "hemp",
	"hence", "herb", "herd", "here", "hero", "heroic", "heron", "herself",
	"hertz", "hewn", "hick", "hicks", "hidden", "hide", "high", "higher",
	"highest", "highway", "hike", "hill", "hilly", "hilt", "himself", "hind",
	"hinge", "hint", "hippo", "hippy", "hire", "hiss", "history", "hitch", "hive",
	"hoagy", "hoard", "hobby", "hobo", "hock", "hogan", "hold", "holdup", "hole",
	"holiday", "hollow", "holly", "home", "hone", "honest", "honey", "honk",
	"honor", "hooch", "hood", "hoof", "hook", "hookup", "hoop", "hoot", "hope",
	"horde", "horn", "horny", "horse", "hose", "hospital", "host", "hotel",
	"hound", "hour", "house", "hove", "hovel", "hover", "howdy", "however",
	"howl", "hubbub", "hubby", "hued", "huff", "huge", "hulk", "hull", "human",
	"humid", "humor", "hump", "humus", "hunch", "hundred", "hung", "hungry",
	"hunk", "hunt", "hunter", "hurl", "hurrah", "hurried", "hurry", "hurt",
	"husband", "hush", "husky", "hutch", "hydra", "hyena", "hying", "hymen",
	"hymn", "hymnal", "iambic", "ibex", "ibis", "icing", "icky", "icon", "idea",
	"ideal", "identity", "idiom", "idiot", "idle", "idol", "idyll", "iffy",
	"igloo", "image", "imagine", "imbue", "immediately", "impel", "import",
	"importance", "important", "impossible", "improve", "impute", "inane",
	"inapt", "incest", "inch", "incident", "include", "including", "income",
	"increase", "incur", "indeed", "independent", "index", "indian", "indicate",
	"individual", "industrial", "industry", "inept", "inert", "infect", "infer",
	"infix", "influence", "information", "ingot", "inhere", "inlay", "inlet",
	"inner", "input", "insect", "inset", "inside", "instance", "instant",
	"instead", "instrument", "insult", "intend", "inter", "interest", "interior",
	"into", "introduced", "inure", "invented", "invoke", "involved", "iota",
	"irate", "iris", "iron", "irony", "island", "islands", "isle", "isn't",
	"issue", "itch", "it'd", "item", "items", "it'll", "itself", "ivory", "jack",
	"jacket", "jade", "jail", "japan", "jazz", "jazzy", "jeep", "jejune", "jelly",
	"jerk", "jerky", "jersey", "jest", "jewel", "jibe", "jiffy", "jilt", "jimmy",
	"jinx", "jive", "jock", "jockey", "john", "johns", "join", "joined", "joint",
	"joke", "jolly", "jolt", "jostle", "joule", "journey", "joust", "jowl",
	"judge", "judo", "juggle", "juggling", "juice", "juicy", "julep", "jumbo",
	"jump", "jumpy", "junco", "jungle", "junk", "junky", "junta", "juror", "jury",
	"just", "jute", "kale", "kapok", "karate", "karma", "kazoo", "keel", "keen",
	"keep", "keeper", "kelp", "kept", "ketch", "keyed", "keys", "khaki", "khan",
	"kick", "kidney", "kids", "kill", "kind", "king", "kingdom", "kink", "kinky",
	"kiosk", "kiss", "kitchen", "kite", "kites", "kitty", "kiwi", "knack",
	"knead", "knee", "kneel", "knelt", "knew", "knife", "knit", "knob", "knock",
	"knoll", "knot", "know", "knowledge", "known", "koala", "kudzu", "label",
	"labia", "labor", "lace", "lack", "lacy", "laden", "ladle", "lady", "lager",
	"lagoon", "laid", "lain", "lair", "laity", "lake", "lamb", "lame", "lament",
	"lamp", "lance", "land", "landlord", "lane", "language", "lanky", "lapel",
	"lapse", "larch", "lard", "large", "larger", "largest", "lark", "larva",
	"lash", "lass", "lasso", "last", "latch", "late", "later", "latest", "latex",
	"lath", "lathe", "latin", "laud", "laugh", "launch", "lava", "lavender",
	"lawn", "layers", "laze", "lazy", "leach", "lead", "leader", "leaf", "leafy",
	"leak", "leaky", "lean", "leap", "leaping", "leapt", "learn", "lease",
	"leash", "least", "leather", "leave", "leaving", "ledge", "leech", "leek",
	"leer", "leery", "leeway", "left", "lefty", "legal", "leggy", "legion",
	"lemma", "lemon", "lend", "length", "lens", "lent", "leper", "less", "lessee",
	"lesson", "lest", "letter", "letters", "levee", "level", "levels", "lever",
	"levy", "lewd", "lexicon", "liar", "libel", "libido", "library", "lice",
	"lick", "lied", "lien", "lieu", "life", "lift", "light", "like", "likely",
	"liken", "lilac", "lilt", "lily", "limb", "limbo", "lime", "limit", "limited",
	"limits", "limp", "linden", "line", "linen", "lingo", "link", "lint", "lion",
	"lionfish", "lipid", "lips", "liquid", "lisle", "lisp", "list", "listen",
	"lithe", "little", "live", "lived", "liven", "livid", "living", "load",
	"loaf", "loam", "loamy", "loan", "loath", "lobby", "lobe", "local", "locate",
	"location", "loci", "lock", "locket", "locus", "lodge", "loft", "lofty",
	"loge", "logic", "loin", "loiter", "loll", "lone", "lonely", "long", "longer",
	"look", "loom", "loon", "loop", "loose", "loot", "lope", "lord", "lore",
	"lose", "loss", "lost", "lotus", "loud", "louse", "lousy", "louver", "love",
	"lovely", "lower", "loyal", "lucid", "luck", "lucky", "lucre", "lull",
	"lumbar", "lump", "lumpy", "lunar", "lunch", "lung", "lunge", "lungs",
	"lurch", "lure", "lurid", "lurk", "lush", "lust", "lusty", "lute", "lying",
	"lymph", "lynch", "lynx", "lyric", "mace", "machine", "machinery", "macho",
	"macro", "madam", "made", "madman", "madness", "magic", "magical", "magma",
	"magnet", "maid", "mail", "maim", "main", "mainly", "major", "make", "maker",
	"making", "malady", "male", "mall", "malt", "mambo", "mamma", "mammal",
	"managed", "mane", "mange", "mania", "manic", "manna", "manner", "manor",
	"mans", "manse", "mansion", "mantle", "manufacturing", "many", "maple",
	"marble", "march", "mare", "maria", "marine", "mark", "market", "marks",
	"marlin", "married", "marrow", "marry", "mars", "marsh", "mart", "mash",
	"mask", "mason", "masque", "mass", "massage", "mast", "master", "match",
	"mate", "material", "math", "mathematics", "matte", "matter", "maul", "mauve",
	"maxim", "maxima", "maximum", "maybe", "mayhem", "mayo", "mayor", "maze",
	"mead", "meadow", "meal", "mealy", "mean", "means", "meant", "measure",
	"meat", "meaty", "mecca", "medal", "media", "medic", "medical", "medicine",
	"medley", "meek", "meet", "meeting", "meld", "mellow", "melon", "melt",
	"melted", "member", "memo", "memoir", "memory", "menace", "mend", "mental",
	"menu", "mercy", "mere", "merely", "merge", "merit", "merlin", "merry",
	"mesa", "mescal", "mesh", "mess", "messy", "metal", "mete", "meter", "method",
	"metro", "mica", "mice", "middle", "midge", "midnight", "midst", "mien",
	"miff", "might", "mighty", "mike", "milch", "mild", "mildew", "mile", "miles",
	"military", "milk", "milky", "mill", "mills", "mimic", "mince", "mind",
	"mine", "minerals", "mini", "minim", "minister", "mink", "minnow", "minor",
	"mint", "minus", "minute", "mirage", "mire", "mirror", "mirth", "miser",
	"misery", "miss", "missing", "mission", "mist", "mistake", "misty", "mite",
	"mitt", "mixture", "moan", "moaning", "moat", "mock", "modal", "mode",
	"model", "models", "modem", "modern", "modesty", "modish", "moire", "moist",
	"molar", "mold", "mole", "molecular", "moll", "molt", "molten", "moment",
	"momentum", "mommy", "money", "mongolia", "monk", "monkey", "monks",
	"monster", "month", "mood", "moody", "moon", "moonrise", "moor", "moose",
	"moot", "moral", "morale", "more", "morn", "morning", "moron", "morsel",
	"mosaic", "moss", "mossy", "most", "mostly", "motel", "moth", "mother",
	"motif", "motion", "motor", "motto", "mound", "mount", "mountain", "mourn",
	"mouse", "mousy", "mouth", "move", "movement", "movie", "moving", "much",
	"muck", "mucus", "muddy", "muff", "muffin", "muggle", "muggy", "mulch",
	"mule", "mull", "mummy", "munch", "mural", "murk", "murky", "muscle", "muse",
	"museum", "mush", "mushy", "music", "musical", "musk", "must", "musty",
	"mute", "mutt", "mynah", "myopia", "myrrh", "myself", "mysterious", "myth",
	"nadir", "naiad", "nail", "nails", "naive", "naked", "name", "named", "names",
	"narnia", "nary", "nasal", "nasty", "natal", "nation", "national", "native",
	"natty", "natural", "naturally", "nature", "naval", "nave", "navel", "navy",
	"near", "nearby", "nearer", "nearest", "nearly", "neat", "neath", "necessary",
	"neck", "necklace", "need", "needed", "needle", "needs", "needy", "negate",
	"negative", "neighbor", "neighborhood", "neon", "nerve", "nervous", "nest",
	"network", "neuron", "never", "newel", "news", "newspaper", "newt", "newton",
	"next", "nibs", "nice", "nicety", "niche", "nick", "niece", "nigh", "night",
	"nimbus", "nine", "ninth", "noble", "nobody", "nodal", "nodded", "node",
	"noel", "noise", "noisy", "nomad", "nonce", "none", "nook", "noon", "noose",
	"norm", "normal", "north", "norway", "nose", "notch", "note", "noted",
	"notes", "nothing", "notice", "noun", "nova", "novel", "november", "nuance",
	"nuclei", "nude", "nudge", "null", "numb", "number", "numeral", "nurse",
	"nuts", "nylon", "nymph", "oaken", "oases", "oasis", "oath", "obese", "obey",
	"object", "objects", "oboe", "obscure", "observe", "obsolete", "obtain",
	"occasionally", "occur", "ocean", "octal", "octave", "octet", "october",
	"oddball", "odium", "o'er", "offal", "offend", "offer", "office", "officer",
	"official", "often", "ogle", "ogre", "oily", "okay", "olden", "older",
	"oldest", "olive", "omega", "omen", "omens", "omit", "once", "onion", "only",
	"onset", "onto", "onus", "onward", "onyx", "ooze", "opal", "opals", "open",
	"opening", "opera", "operation", "opinion", "opium", "opportunity",
	"opposite", "optic", "opus", "oracle", "oral", "orange", "orate", "orbit",
	"orchid", "ordain", "order", "ordinary", "organ", "organization", "organized",
	"orgy", "origin", "original", "ornery", "osier", "other", "otter", "ouch",
	"ought", "ounce", "ourselves", "oust", "outer", "outline", "outside", "oval",
	"ovary", "oven", "over", "overt", "owing", "owner", "oxen", "oxide", "oxygen",
	"ozone", "pace", "pack", "package", "packet", "pact", "paddy", "padre",
	"paean", "pagan", "page", "pages", "paid", "pail", "pain", "paint", "pair",
	"palace", "pale", "pall", "palm", "palsy", "panda", "pane", "panel", "pang",
	"panic", "pansy", "pant", "pants", "panty", "papa", "papal", "papaw", "paper",
	"paragraph", "parallel", "parch", "parchment", "pardon", "pare", "parent",
	"paris", "park", "parks", "parody", "parry", "parse", "part", "particles",
	"particular", "particularly", "partly", "parts", "party", "pasha", "pass",
	"passage", "past", "paste", "pastry", "pasty", "patch", "pate", "path",
	"patio", "patsy", "pattern", "patty", "pause", "pave", "pawn", "payday",
	"peace", "peach", "peak", "peal", "pear", "pearl", "pease", "peat", "pebble",
	"pecan", "peck", "pedal", "peed", "peek", "peel", "peep", "peer", "pelt",
	"penal", "pence", "pencil", "penny", "penrose", "pent", "peony", "people",
	"pepper", "peppy", "percent", "perch", "perfect", "perfectly", "perhaps",
	"peril", "period", "perk", "perky", "perpetual", "person", "personal", "pert",
	"peruse", "pest", "pests", "petal", "peter", "petty", "pewee", "pewter",
	"phase", "phlox", "phoenix", "phone", "phony", "photo", "phrase", "phyla",
	"physic", "physical", "piano", "pica", "pick", "pickup", "picky", "picture",
	"pictured", "piece", "pier", "pierce", "piety", "piggy", "pike", "pile",
	"pill", "pilot", "pimp", "pinch", "pine", "ping", "pinion", "pink", "pint",
	"pinto", "pious", "pipe", "piper", "pique", "pitch", "pith", "pithy", "pity",
	"pivot", "pixel", "pixie", "pixy", "pizza", "place", "plague", "plaid",
	"plain", "plan", "plane", "planet", "plank", "planned", "planning", "plant",
	"plastic", "plate", "plates", "play", "plaza", "plea", "plead", "pleasant",
	"please", "pleasure", "pleat", "pledge", "plenty", "plod", "plop", "plot",
	"plow", "pluck", "plug", "plum", "plumb", "plume", "plump", "plunk", "plural",
	"plus", "plush", "plushy", "poach", "pocket", "podia", "poem", "poesy",
	"poet", "poetry", "point", "poise", "poke", "polar", "pole", "police",
	"policeman", "polio", "political", "polka", "poll", "polo", "pomp", "pond",
	"pony", "pooch", "pooh", "pool", "poop", "poor", "pope", "poppy", "popular",
	"population", "porch", "pore", "pork", "porous", "port", "pose", "posh",
	"posit", "position", "positive", "posse", "possible", "possibly", "post",
	"posy", "potatoes", "pouch", "pound", "pour", "pout", "powder", "power",
	"powerful", "practical", "practice", "pram", "prank", "pray", "preen",
	"prefix", "prep", "prepare", "present", "president", "press", "pressure",
	"pretty", "prevent", "previous", "prey", "price", "prick", "pride", "prig",
	"prim", "prime", "primitive", "primp", "prince", "principal", "principle",
	"print", "printed", "prior", "prism", "prissy", "private", "privy", "prize",
	"probably", "probe", "problem", "process", "prod", "produce", "product",
	"production", "prof", "program", "progress", "prom", "promised", "prone",
	"prong", "proof", "prop", "proper", "properly", "property", "prose",
	"protection", "proud", "prove", "provide", "prow", "prowl", "proxy", "prune",
	"psalm", "psych", "public", "puck", "puff", "puffy", "puke", "pull", "pulp",
	"pulse", "puma", "pump", "punch", "punish", "punk", "punt", "puny", "pupal",
	"pupil", "puppy", "pure", "purge", "purl", "purple", "purpose", "purr",
	"purse", "push", "pussy", "putt", "putting", "putty", "pygmy", "pyre",
	"pyrite", "quack", "quad", "quaff", "quail", "quake", "qualm", "quark",
	"quarry", "quart", "quarter", "quash", "quasi", "quay", "queasy", "queen",
	"queer", "quell", "query", "quest", "question", "queue", "quick", "quickly",
	"quid", "quiet", "quietly", "quill", "quilt", "quip", "quirk", "quit",
	"quite", "quiz", "quota", "quote", "rabbi", "rabbit", "rabid", "race", "rack",
	"racy", "radar", "radii", "radio", "radium", "radon", "raft", "rage", "raid",
	"rail", "railroad", "rain", "rainy", "raise", "rajah", "rake", "rally",
	"ramp", "ranch", "randy", "rang", "range", "rangy", "rank", "rant", "rape",
	"rapid", "rapidly", "rapt", "rare", "rascal", "rash", "rasp", "rate",
	"rather", "ratio", "rattle", "rave", "ravel", "raven", "rays", "raze",
	"razor", "reach", "read", "reader", "ready", "real", "realize", "realm",
	"ream", "reap", "rear", "reason", "rebel", "rebut", "recall", "receive",
	"recent", "recently", "recipe", "recognize", "record", "recur", "redeem",
	"reduce", "reed", "reedy", "reef", "reek", "reel", "reeve", "refer",
	"refused", "regal", "region", "regular", "reign", "rein", "related",
	"relationship", "relax", "relay", "relic", "religious", "remain",
	"remarkable", "remedy", "remember", "remit", "remove", "renal", "rend",
	"renown", "rent", "repeat", "repel", "repent", "replace", "replied", "report",
	"represent", "require", "research", "resin", "resort", "respect", "rest",
	"result", "retch", "return", "reveal", "revel", "review", "revved", "rhea",
	"rheum", "rhino", "rhyme", "rhythm", "rice", "rich", "rick", "ride", "ridge",
	"riding", "rifle", "rift", "right", "rigid", "rill", "rime", "ring", "rink",
	"rinse", "riot", "ripe", "ripen", "rise", "risen", "rising", "risk", "risky",
	"rite", "rival", "riven", "river", "rivet", "roach", "road", "roam", "roar",
	"roast", "robe", "robin", "robot", "rock", "rocket", "rocky", "rode", "rodeo",
	"roger", "rogue", "roil", "role", "roll", "roman", "romp", "rood", "roof",
	"rook", "rookie", "room", "roomy", "roost", "root", "rope", "rose", "rosy",
	"rotor", "rouge", "rough", "round", "rouse", "rout", "route", "rove", "rowdy",
	"royal", "rubbed", "rubber", "rube", "rubric", "ruby", "ruddy", "rude",
	"ruin", "rule", "ruler", "rummy", "rump", "rumpus", "rune", "rung", "running",
	"runt", "rupee", "rural", "ruse", "rush", "rusk", "rust", "rusty", "sable",
	"sack", "saddle", "safari", "safe", "safety", "saga", "sage", "sago", "said",
	"sail", "saint", "sake", "salad", "sale", "saline", "sally", "salmon",
	"salon", "salt", "salty", "salve", "salvo", "samba", "same", "sand", "sandal",
	"sandy", "sane", "sang", "sank", "sans", "sappy", "sari", "sash",
	"satellites", "satin", "satisfied", "satyr", "sauce", "saucy", "save",
	"saved", "savvy", "sawyer", "scab", "scald", "scale", "scalp", "scam",
	"scamp", "scan", "scant", "scar", "scare", "scared", "scarf", "scary", "scat",
	"scene", "scent", "school", "science", "scientific", "scientist", "scion",
	"scoff", "scold", "scoop", "scoot", "scope", "score", "scorn", "scour",
	"scout", "scowl", "scram", "scrap", "scrape", "screen", "screw", "scrub",
	"scuba", "scud", "scuff", "scull", "scum", "scurry", "seal", "seam", "seamy",
	"sear", "search", "sears", "season", "seat", "second", "secret", "sect",
	"section", "sedan", "sedge", "seed", "seedy", "seeing", "seek", "seem",
	"seems", "seen", "seep", "seethe", "seize", "seldom", "select", "selection",
	"self", "sell", "semi", "send", "sense", "sent", "sentence", "sentry",
	"sepal", "separate", "sepia", "septa", "sequin", "sera", "serf", "serge",
	"series", "serious", "serum", "serve", "service", "servo", "sets", "setting",
	"settle", "settlers", "setup", "seven", "sever", "several", "severe", "sewn",
	"sexy", "shack", "shad", "shade", "shadow", "shady", "shaft", "shag", "shah",
	"shake", "shaken", "shaking", "shaky", "shale", "shall", "shallow", "sham",
	"shame", "shank", "shape", "shard", "share", "shark", "sharp", "shave",
	"shawl", "sheaf", "shear", "sheath", "shed", "she'd", "sheen", "sheep",
	"sheer", "sheet", "sheik", "shelf", "shell", "shells", "shelter", "shied",
	"shift", "shill", "shim", "shin", "shine", "shinning", "shiny", "ship",
	"shire", "shirk", "shirt", "shoal", "shock", "shod", "shoe", "shone", "shoo",
	"shook", "shoot", "shop", "shore", "short", "shorter", "shot", "should",
	"shoulder", "shout", "shove", "show", "shown", "showy", "shrank", "shred",
	"shrew", "shrike", "shrub", "shrug", "shuck", "shun", "shunt", "shut",
	"sibyl", "sick", "side", "sides", "sidle", "siege", "sieve", "sift", "sigh",
	"sight", "sigma", "sign", "signal", "silence", "silent", "silk", "silky",
	"sill", "silly", "silo", "silt", "silver", "similar", "simple", "simplest",
	"simply", "since", "sine", "sinew", "sing", "singe", "single", "sink",
	"sinus", "sire", "siren", "sisal", "sister", "site", "sitting", "situation",
	"sixth", "sixty", "size", "skate", "skeet", "skew", "skid", "skied", "skiff",
	"skill", "skim", "skimp", "skimpy", "skin", "skip", "skirt", "skit", "skulk",
	"skull", "skunk", "slab", "slabs", "slack", "slag", "slain", "slake", "slam",
	"slang", "slant", "slap", "slash", "slat", "slate", "slave", "slay", "sled",
	"sleek", "sleep", "sleet", "slept", "slew", "slice", "slick", "slid", "slide",
	"slight", "slightly", "slim", "slime", "slimy", "sling", "slip", "slipped",
	"slit", "sliver", "slob", "sloe", "slog", "sloop", "slop", "slope", "slosh",
	"slot", "sloth", "slow", "slowly", "slug", "sluice", "slum", "slump", "slung",
	"slur", "slurp", "smack", "small", "smaller", "smallest", "smart", "smash",
	"smear", "smell", "smelt", "smile", "smirk", "smith", "smithy", "smog",
	"smoke", "smoky", "smooth", "smug", "smut", "snack", "snafu", "snag", "snail",
	"snake", "snap", "snare", "snarl", "snatch", "sneak", "sneer", "sniff",
	"snip", "snipe", "snob", "snoop", "snore", "snort", "snout", "snow", "snowy",
	"snub", "snuff", "snug", "soak", "soap", "soapy", "soar", "sober", "social",
	"society", "sock", "soda", "sofa", "soft", "soften", "softly", "soggy",
	"soil", "solar", "sold", "soldier", "sole", "solemn", "solid", "solo",
	"solution", "solve", "some", "somebody", "somehow", "someone", "something",
	"sometime", "somewhere", "sonar", "song", "sonic", "sonny", "soon", "soot",
	"sooth", "sore", "sorry", "sort", "sough", "soul", "sound", "soup", "sour",
	"source", "south", "southern", "sown", "soya", "space", "spade", "span",
	"spar", "spare", "spark", "spasm", "spat", "spate", "spawn", "spay", "speak",
	"spear", "spec", "special", "species", "specific", "speck", "sped", "speech",
	"speed", "spell", "spend", "spent", "sperm", "spew", "spice", "spicy",
	"spider", "spike", "spiky", "spill", "spilt", "spin", "spine", "spiny",
	"spire", "spirit", "spit", "spite", "splat", "splay", "spline", "split",
	"spoil", "spoke", "spoken", "spoof", "spook", "spooky", "spool", "spoon",
	"spore", "sport", "spot", "spout", "sprain", "spray", "spread", "spree",
	"sprig", "spring", "spruce", "spud", "spume", "spun", "spunk", "spur",
	"spurn", "spurt", "squad", "square", "squat", "squaw", "squid", "squint",
	"stab", "stack", "staff", "stag", "stage", "staid", "stain", "stair",
	"stairs", "stake", "stale", "stalk", "stall", "stamp", "stance", "stand",
	"standard", "stank", "staph", "star", "stare", "stared", "stark", "start",
	"stash", "state", "statement", "station", "statue", "stave", "stay", "stead",
	"steady", "steak", "steal", "steam", "steed", "steel", "steep", "steer",
	"stein", "stem", "stems", "step", "stepped", "stern", "stew", "stick",
	"stiff", "stile", "still", "stilt", "sting", "stingy", "stink", "stint",
	"stir", "stock", "stoic", "stoke", "stole", "stomach", "stomp", "stone",
	"stony", "stood", "stool", "stoop", "stop", "stopped", "store", "storey",
	"stork", "storm", "story", "stout", "stove", "stow", "strafe", "straight",
	"strange", "stranger", "strap", "straw", "stray", "stream", "street",
	"strength", "stretch", "strewn", "strike", "string", "strip", "stroll",
	"strong", "stronger", "strop", "struck", "structure", "struggle", "strum",
	"strut", "stub", "stuck", "stud", "student", "studied", "study", "studying",
	"stuff", "stuffy", "stump", "stun", "stung", "stunk", "stunt", "style",
	"styli", "suave", "subject", "substance", "subtly", "success", "successful",
	"such", "suck", "sudden", "suddenly", "suds", "sugar", "suggest", "suit",
	"suite", "sulk", "sulky", "sully", "sultry", "sumac", "summer", "summon",
	"sung", "sunk", "sunlight", "sunny", "sunset", "super", "supper", "supply",
	"support", "suppose", "sure", "surf", "surface", "surge", "surprise",
	"surrounded", "sushi", "swab", "swag", "swain", "swam", "swami", "swamp",
	"swampy", "swan", "swank", "swap", "swarm", "swat", "swath", "sway", "swear",
	"sweat", "sweaty", "sweep", "sweet", "swell", "swept", "swift", "swig",
	"swim", "swimming", "swine", "swing", "swipe", "swirl", "swish", "swoop",
	"sword", "swore", "sworn", "swum", "swung", "syllable", "sylvan", "symbol",
	"synod", "syrup", "system", "table", "taboo", "tabu", "tacit", "tack",
	"tacky", "tact", "taffy", "tail", "taint", "take", "taken", "talc", "tale",
	"tales", "talk", "tall", "tallow", "tally", "talon", "tame", "tamp", "tang",
	"tango", "tangy", "tank", "tansy", "tape", "taper", "tapir", "tardy",
	"tariff", "tarry", "tart", "task", "taste", "tasty", "tattle", "tatty",
	"taught", "taunt", "taut", "tavern", "tawny", "taxi", "teach", "teacher",
	"teal", "team", "tear", "tears", "tease", "teat", "teem", "teen", "teensy",
	"teeth", "telephone", "television", "telex", "tell", "temperature", "tempo",
	"tempt", "tend", "tenet", "tenon", "tenor", "tense", "tensor", "tent",
	"tenth", "tepee", "tepid", "term", "tern", "terrible", "terry", "terse",
	"test", "testy", "text", "than", "thank", "that", "thaw", "thee", "theft",
	"their", "them", "theme", "themselves", "then", "theory", "there",
	"therefore", "these", "theta", "they", "thick", "thief", "thigh", "thin",
	"thine", "thing", "think", "third", "thirty", "this", "thong", "thorn",
	"thorny", "those", "thou", "though", "thought", "thousand", "thread", "three",
	"threw", "throat", "throb", "throes", "through", "throughout", "throw",
	"thrown", "thrum", "thud", "thug", "thumb", "thump", "thus", "thyme", "tibia",
	"tick", "ticket", "tidal", "tidbit", "tide", "tidy", "tied", "tier", "tiger",
	"tight", "tightly", "tilde", "tile", "till", "tilt", "time", "timid", "tine",
	"tinge", "tint", "tiny", "tipsy", "tire", "tired", "titan", "tithe", "title",
	"toad", "toady", "toast", "tobacco", "today", "tofu", "together", "togs",
	"toil", "toilet", "token", "told", "toll", "tomb", "tome", "tomorrow",
	"tonal", "tone", "tong", "tongue", "tonic", "tonight", "tonsil", "tony",
	"took", "tool", "toot", "tooth", "topaz", "topic", "topple", "torch", "tore",
	"torn", "torso", "tort", "torus", "toss", "total", "tote", "totem", "touch",
	"tough", "tour", "tout", "toward", "towel", "tower", "town", "toxic", "toxin",
	"trace", "track", "tract", "trade", "traffic", "trail", "train", "trait",
	"tram", "tramp", "transportation", "trap", "trash", "travel", "trawl", "tray",
	"tread", "treat", "treated", "treble", "tree", "trek", "trench", "trend",
	"tress", "triad", "trial", "triangle", "tribe", "trick", "tried", "trig",
	"trill", "trim", "trio", "trip", "tripe", "trite", "trod", "troll", "troop",
	"troops", "tropical", "trot", "trouble", "trout", "troy", "truce", "truck",
	"trudge", "true", "truly", "trump", "trunk", "truss", "trust", "truth",
	"tsar", "tuba", "tube", "tuck", "tuft", "tulip", "tulle", "tuna", "tune",
	"tunic", "tunnel", "turf", "turn", "tusk", "tussle", "tutor", "tutu", "twain",
	"tweak", "tweed", "twelve", "twenty", "twice", "twig", "twill", "twin",
	"twine", "twirl", "twist", "twit", "tying", "type", "typical", "typo", "ugly",
	"ulcer", "ultra", "umber", "umpire", "uncle", "under", "underline",
	"understanding", "unhappy", "unify", "union", "unit", "unite", "unity",
	"universe", "unknown", "unless", "until", "unusual", "upend", "uphold",
	"upon", "upper", "uproar", "upset", "uptake", "upward", "urban", "urbane",
	"urea", "urge", "urine", "usage", "useful", "usher", "using", "usual",
	"usually", "usurp", "usury", "utmost", "utter", "vacua", "vague", "vain",
	"vale", "valet", "valid", "valley", "valuable", "value", "valve", "vamp",
	"vane", "vapor", "variety", "various", "vary", "vase", "vast", "vault",
	"veal", "veer", "vegetable", "veil", "vein", "veldt", "vellum", "venal",
	"vend", "venial", "venom", "vent", "verb", "verge", "verity", "verse",
	"vertical", "verve", "very", "vessel", "vessels", "vest", "vetch", "veto",
	"vial", "vicar", "vice", "victory", "video", "view", "vigil", "vile", "villa",
	"village", "vine", "vinyl", "viola", "violet", "virus", "visa", "vise",
	"visit", "visitor", "visor", "vista", "vital", "viva", "vivid", "vixen",
	"vocal", "vogue", "voice", "void", "volt", "volume", "vomit", "vote", "vouch",
	"vowel", "voyage", "vying", "wacky", "wade", "wadi", "wafer", "wage",
	"waggle", "wagon", "wail", "waist", "wait", "waive", "wake", "waken", "wale",
	"walk", "wall", "walls", "waltz", "wand", "wane", "want", "ward", "ware",
	"warm", "warmth", "warn", "warp", "warren", "wart", "warty", "wary", "wash",
	"wasp", "waste", "watch", "water", "watt", "watts", "wave", "wavy", "waxen",
	"waxy", "weak", "weal", "wealth", "wean", "wear", "weary", "weather", "weave",
	"we'd", "wedge", "weed", "weedy", "week", "weeks", "weep", "weigh", "weight",
	"weir", "weird", "welch", "welcome", "weld", "well", "we'll", "wells",
	"welsh", "welt", "went", "wept", "were", "we're", "west", "western", "we've",
	"whack", "whale", "wham", "wharf", "what", "whatever", "wheat", "wheel",
	"whelk", "whelp", "when", "whenever", "where", "wherever", "whet", "whether",
	"which", "whiff", "while", "whim", "whine", "whinny", "whip", "whir", "whirl",
	"whisk", "whispered", "whistle", "whit", "white", "whiz", "whoa", "who'd",
	"whole", "whom", "whoop", "whoosh", "whose", "wick", "wide", "widely",
	"widen", "widow", "width", "wield", "wife", "wild", "wile", "will", "willing",
	"wills", "wilt", "wily", "wince", "winch", "wind", "window", "windy", "wine",
	"wing", "wink", "wino", "winter", "wipe", "wire", "wiry", "wise", "wish",
	"wisp", "wispy", "witch", "with", "within", "without", "witty", "wive",
	"woke", "wolf", "woman", "womb", "women", "wonder", "wonderful", "wont",
	"won't", "wood", "wooden", "woods", "woody", "wool", "woozy", "word", "wordy",
	"wore", "work", "worker", "world", "worm", "wormy", "worn", "worried",
	"worry", "worse", "worst", "worth", "would", "wound", "wove", "woven",
	"wrack", "wrap", "wrapped", "wrath", "wreak", "wreck", "wrest", "wring",
	"wrist", "writ", "write", "writer", "writhe", "writing", "written", "wrong",
	"wrote", "xenon", "xylem", "yacht", "yank", "yard", "yarn", "yawl", "yawn",
	"yeah", "year", "yearn", "yeast", "yeasty", "yell", "yellow", "yelp",
	"yesterday", "yield", "yodel", "yoga", "yogi", "yoke", "yokel", "yolk",
	"yore", "you'd", "young", "younger", "your", "yourself", "youth", "yucca",
	"yuck", "yule", "zeal", "zealot", "zebra", "zero", "zest", "zeta", "zilch",
	"zinc", "zing", "zone", "zoom",
}

// An alphabet for alternative cryptic passwords, useful for sites with stupid
// password restrictions. This list has well over 64 characters, so it consumes
// a more than 6 bits of entropy per character.
var SmallAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890~!@#$%^&*()_+`-=[]{}|;':\",./<>?"

// An alphabet for alternative slightly-less cryptic passwords, useful for sites
// with very stupid password restrictions. This list has over 64 characters, so
// it consumes a tad more than 6 bits of entropy per character.
var TinyAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890!()%*"
