/**
 * contentValidator.js
 * Flags emails that are technically valid but unacceptable for registration:
 *
 *  1. Offensive / profane local parts
 *  2. Test / throwaway local parts  (test@, temp@, fake@, etc.)
 *  3. Role-based addresses          (admin@, noreply@, support@, etc.)
 *  4. Disposable email providers    (mailinator, guerrillamail, etc.)
 *  5. Sequential / keyboard pattern locals (aaa@, qwerty@, 123@, etc.)
 */

// ---------------------------------------------------------------------------
// 1. Profanity / offensive word list (local part)
//    Keep this as a Set for O(1) lookup. Add words as needed.
// ---------------------------------------------------------------------------
const PROFANE_WORDS = new Set([
  "fuck","fucker","fucking","fucked","fuk","f4ck","fvck",
  "shit","sh1t","sht",
  "ass","arse","asshole","a55",
  "bitch","btch","b1tch",
  "bastard","bastad",
  "cunt","c0nt",
  "dick","d1ck","dik",
  "cock","c0ck",
  "pussy","puss",
  "whore","wh0re",
  "nigga","nigger","n1gger",
  "prick","pr1ck",
  "slut","sl4t",
  "twat","tw4t",
  "wank","wanker",
  "retard","ret4rd",
  "faggot","f4ggot","fag",
  "dildo","d1ldo",
  "porn","p0rn",
  "sex","s3x",
  "nude","nood",
  "rape","r4pe",
  "nazi","n4zi",
  "kill","k1ll",
  "die","dye",
  "hate","h4te",
  "idiot","1diot",
  "moron","mor0n",
  "stupid","5tupid",
]);

// Leet-speak: each char can map to multiple letters — build all variants
const LEET_MAP_MULTI = {
  "0": ["o"],
  "1": ["i", "l"],
  "3": ["e"],
  "4": ["a", "u"],    // f4ck -> fack OR fuck
  "5": ["s"],
  "6": ["g", "b"],
  "7": ["t", "l"],
  "8": ["b"],
  "@": ["a"],
  "+": ["t"],
  "$": ["s"],
};

function leetVariants(str) {
  let variants = [""];
  for (const ch of str.toLowerCase()) {
    const maps = LEET_MAP_MULTI[ch];
    if (maps) {
      const next = [];
      for (const v of variants) for (const m of maps) next.push(v + m);
      variants = next;
    } else {
      variants = variants.map((v) => v + ch);
    }
    if (variants.length > 512) break; // safety cap on combinatorial explosion
  }
  return variants.map((v) => v.replace(/[^a-z]/g, ""));
}

function containsProfanity(local) {
  const variants = leetVariants(local);
  for (const clean of variants) {
    if (PROFANE_WORDS.has(clean)) return { found: true, word: clean };
    for (const word of PROFANE_WORDS) {
      if (clean.includes(word)) return { found: true, word };
    }
  }
  return { found: false };
}

// ---------------------------------------------------------------------------
// 2. Test / throwaway local parts
// ---------------------------------------------------------------------------
const TEST_LOCAL_EXACT = new Set([
  "test","testing","tester","test1","test2","test123","testuser","testaccount",
  "temp","temporary","tmp","tmpuser",
  "fake","fakeuser","fakemail","fakeemail",
  "dummy","dummyuser","dummyemail",
  "sample","example","demo","demouser",
  "placeholder","noemail","nope","none","null","undefined","void",
  "user","user1","user123","myuser","newuser",
  "abc","abcd","abcde","abcdef","abc123","asd","asdf","asdfg",
  "hello","hello123","hi","hey",
  "random","randomuser","anon","anonymous",
  "trash","trashmail","throwaway","throw",
  "junk","junkmail",
  "spam","spamtest","spamme","nospam","antispam",
  "delete","deleted","removed","inactive","disabled",
  "qwerty","qwertyuiop","password","pass123",
  "firstname","lastname","fullname","yourname","myname","name",
  "email","myemail","youremail","emailtest",
  "login","register","signup","account",
  "a","b","c","d","e","f","g","x","y","z",
  "aa","bb","cc","xx","yy","zz",
  "aaa","bbb","ccc","xxx","yyy","zzz",
  "1","12","123","1234","12345","123456","1234567","12345678",
  "111","222","333","000",
]);

const TEST_LOCAL_PATTERNS = [
  /^test[\d_\-.]*$/i,          // test, test1, test_user, test-01
  /^temp[\d_\-.]*$/i,
  /^fake[\d_\-.]*$/i,
  /^dummy[\d_\-.]*$/i,
  /^sample[\d_\-.]*$/i,
  /^demo[\d_\-.]*$/i,
  /^trash[\d_\-.]*$/i,
  /^junk[\d_\-.]*$/i,
  /^spam[\d_\-.]*$/i,
  /[\d_\-.]*(test|temp|fake|dummy|throwaway)[\d_\-.]*$/i,
  /^(.)\1{4,}$/,               // aaaaa, 11111, .....
  /^(abc|xyz|qwerty|asdf)+[\d]*$/i,
  /^[a-z][\d]+$/i,             // a1, b22, x999 — single letter + digits
  /^\d+[a-z]?$/i,              // pure digits like 123456
];

function isTestLocal(local) {
  const l = local.toLowerCase();
  if (TEST_LOCAL_EXACT.has(l)) return { found: true, reason: `"${local}" is a common test/placeholder address` };
  for (const pattern of TEST_LOCAL_PATTERNS) {
    if (pattern.test(l)) return { found: true, reason: `"${local}" matches a test/throwaway pattern` };
  }
  return { found: false };
}

// ---------------------------------------------------------------------------
// 3. Role-based addresses
// ---------------------------------------------------------------------------
const ROLE_ADDRESSES = new Set([
  "admin","administrator","root","webmaster","hostmaster","postmaster",
  "noreply","no-reply","noreply","donotreply","do-not-reply","do_not_reply",
  "support","help","helpdesk","contact","info","information",
  "sales","marketing","billing","accounts","accounting","finance","payments",
  "hr","humanresources","careers","jobs","recruitment","hiring",
  "security","abuse","spam","phishing","legal","compliance","privacy",
  "newsletter","news","announcements","updates","notifications","alerts",
  "service","services","customer","customerservice","customersupport",
  "feedback","survey","press","media","pr","publicrelations",
  "it","ithelp","itsupport","devops","sysadmin","network","ops",
  "dev","developer","developers","api","bot","system","server",
  "team","staff","office","management","manager",
  "mail","email","inbox","outbox","mailbox",
  "bounce","bounces","mailer","mailer-daemon","daemon",
  "unsubscribe","subscribe","list","lists","mailinglist",
  "reply","replies","replies",
]);

function isRoleBased(local) {
  const l = local.toLowerCase().replace(/[^a-z]/g, "");
  if (ROLE_ADDRESSES.has(l)) return { found: true, reason: `"${local}" is a role/functional address, not a personal inbox` };
  return { found: false };
}

// ---------------------------------------------------------------------------
// 4. Disposable email providers (domain)
// ---------------------------------------------------------------------------
const DISPOSABLE_DOMAINS = new Set([
  // Classic
  "mailinator.com","guerrillamail.com","guerrillamail.net","guerrillamail.org",
  "guerrillamail.biz","guerrillamail.de","guerrillamail.info",
  "throwam.com","throwam.net",
  "yopmail.com","yopmail.fr","yopmail.net",
  "maildrop.cc","maildrop.de",
  "trashmail.com","trashmail.me","trashmail.net","trashmail.io","trashmail.org",
  "trashmail.at","trashmail.xyz",
  "tempmail.com","tempmail.net","tempmail.org","temp-mail.org","temp-mail.io",
  "tempr.email","tmpmail.net","tmpmail.org",
  "sharklasers.com","guerrillamailblock.com","grr.la","guerrillamail.info",
  "spam4.me","spamgourmet.com","spamgourmet.net","spamgourmet.org",
  "mailnull.com","spamgourmet.com",
  "fakeinbox.com","fakeinbox.net",
  "dispostable.com","disposableaddress.com",
  "crazymailing.com","e4ward.com",
  "spamfree24.org","spamfree24.de","spamfree24.eu","spamfree24.info","spamfree24.net",
  "nobullshit.net","nospamfor.us","nospammail.net","amilegit.com","amirisgod.com",
  "bugmenot.com",
  "getonemail.com","getonemail.net",
  "mailexpire.com","mailnew.com","mailsiphon.com","mailzilla.com",
  "meltmail.com","mierdamail.com","mintemail.com",
  "mt2009.com","mt2014.com",
  "mytrashmail.com","neverbox.com","nowmymail.com",
  "objectmail.com","obobbo.com","odaymail.com",
  "oneoffmail.com","onewaymail.com",
  "pookmail.com","proxymail.eu",
  "rcpt.at","recode.me","recursor.net","regbypass.com",
  "safetymail.info","shieldedmail.com","skeefmail.com","sneakemail.com",
  "sofort-mail.de","spam.la","spamavert.com","spambog.com","spambog.de",
  "spambob.net","spambob.org","spambox.info","spambox.us",
  "spamcero.com","spamcon.org","spamcorptastic.com",
  "spoofmail.de","super-auswahl.de","supergreatmail.com",
  "thisisnotmyrealemail.com","throwam.com",
  "trbvm.com","trillianpro.com","turual.com",
  "twinmail.de","tyldd.com",
  "uggsrock.com","uroid.com","us.af",
  "veryrealemail.com","viditag.com","viewcastmedia.com","viewcastmedia.net",
  "viewcastmedia.org",
  "webemail.me","webm4il.info","wegwerfmail.de","wegwerfmail.net","wegwerfmail.org",
  "whatpaas.com","whyspam.me","willselfdestruct.com","wilemail.com",
  "wuzupmail.net","www.e4ward.com","wyvernia.net",
  "xagloo.com","xemaps.com","xents.com","xmaily.com","xoxy.net","xyzfree.net",
  "yep.it","yogamaven.com","yomail.info","yopmail.gq",
  "zippymail.info","zoaxe.com","zoemail.net","zoemail.org","zomg.info",
  // Modern / popular disposable
  "10minutemail.com","10minutemail.net","10minutemail.org","10minutemail.co.uk",
  "10minemail.com","10minutemail.de","10minutemail.ru",
  "20minutemail.com","20minutemail.it",
  "60minutemail.com",
  "disposableemailaddresses.com","disposableemailaddresses.emailmiser.com",
  "discard.email","discardmail.com","discardmail.de",
  "emailondeck.com",
  "filzmail.com","fleckens.hu",
  "garbagemail.org","get1mail.com","getairmail.com","getmails.eu",
  "gmailnull.com","haltospam.com","hatespam.org",
  "hidemail.de","hidzz.com","hochsitze.com",
  "ieh-mail.de","ihateyoualot.info","inoutmail.de","inoutmail.eu","inoutmail.info",
  "inoutmail.net","internet-e-mail.de","internet-mail.org",
  "jetable.com","jetable.fr.nf","jetable.net","jetable.org",
  "jsrsolutions.com","junk.to","junkmail.gq","junkmail.ro",
  "kasmail.com","kaspop.com","keepmymail.com","killmail.com","killmail.net",
  "klassmaster.com","klassmaster.net",
  "klzlk.com","koszmail.pl","kurzepost.de",
  "lawlita.com","lazyinbox.com","letthemeatspam.com","lhsdv.com",
  "lifebyfood.com","link2mail.net","litedrop.com","lol.ovpn.to",
  "lolfreak.net","lookugly.com",
  "lortemail.dk","lovemeleaveme.com","lr78.com",
  "lukemail.net","lukop.dk",
  "m21.cc","mail-temporaire.fr","mail.mezimages.net","mail2rss.org",
  "mail333.com","mailbidon.com","mailbiz.biz","mailblocks.com",
  "mailbucket.org","mailcat.biz","mailcatch.com","mailde.de","mailde.info",
  "maildu.de","mailfree.ga","mailfreeonline.com","mailguard.me",
  "mailimate.com","mailin8r.com","mailinater.com",
  "mailismagic.com","mailme.gq","mailme.ir","mailme.lv",
  "mailme24.com","mailmetrash.com",
  "mailmoat.com","mailnesia.com","mailnew.com",
  "mailpick.biz","mailproxsy.com","mailquack.com",
  "mailrock.biz","mailseal.de","mailshell.com","mailscrap.com",
  "mailslapping.com","mailslite.com",
  "mailspeed.de","mailtemp.info","mailtome.de","mailtothis.com",
  "mailtraps.com","mailtrash.net","mailtrix.net","mailtv.net",
  "mailzi.com","mailzilla.org",
]);

function isDisposable(domain) {
  const d = domain.toLowerCase();
  if (DISPOSABLE_DOMAINS.has(d)) return { found: true, reason: `"${domain}" is a known disposable/temporary email provider` };
  // Also catch subdomains of disposable providers
  const parts = d.split(".");
  for (let i = 1; i < parts.length - 1; i++) {
    const parent = parts.slice(i).join(".");
    if (DISPOSABLE_DOMAINS.has(parent)) return { found: true, reason: `"${domain}" is a subdomain of disposable provider "${parent}"` };
  }
  return { found: false };
}

// ---------------------------------------------------------------------------
// 5. Main content validation function
// ---------------------------------------------------------------------------
function validateContent(email) {
  const trimmed = email.trim().toLowerCase();
  const atIdx = trimmed.lastIndexOf("@");
  if (atIdx === -1) return { valid: false, flags: [] }; // syntax not our job here

  const local = trimmed.slice(0, atIdx);
  const domain = trimmed.slice(atIdx + 1);

  const flags = [];

  // Check profanity
  const profanity = containsProfanity(local);
  if (profanity.found) {
    flags.push({
      type: "profanity",
      severity: "block",
      message: `Local part contains inappropriate content ("${profanity.word}")`,
    });
  }

  // Check test/throwaway local
  const testLocal = isTestLocal(local);
  if (testLocal.found) {
    flags.push({
      type: "test_address",
      severity: "block",
      message: testLocal.reason,
    });
  }

  // Check role-based
  const role = isRoleBased(local);
  if (role.found) {
    flags.push({
      type: "role_address",
      severity: "warn",    // warn, not block — some orgs legitimately sign up with these
      message: role.reason,
    });
  }

  // Check disposable domain
  const disposable = isDisposable(domain);
  if (disposable.found) {
    flags.push({
      type: "disposable_domain",
      severity: "block",
      message: disposable.reason,
    });
  }

  const blocked = flags.some((f) => f.severity === "block");
  return {
    valid: !blocked,
    flags,
    summary: blocked
      ? flags.find((f) => f.severity === "block").message
      : flags.length > 0
      ? flags.map((f) => f.message).join("; ")
      : null,
  };
}

module.exports = { validateContent };
