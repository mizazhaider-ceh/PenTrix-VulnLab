'use strict';

// M13 career path: API Hacker.
// Ten API flaws in increasing order of trickiness: leaked records, mass
// assignment, forged tokens, forgotten endpoints. Prerequisite: finish the
// Zero to Web Pentester path first.

module.exports = {
  id: 'api-hacker',
  name: 'API Hacker',
  tagline: 'APIs trust the client too much. Prove it ten times.',
  difficulty: 'Intermediate',
  prerequisites: ['zero-to-web-pentester'],
  description: '<p>APIs run the modern web, and they trust the client far too much. Every mobile app, dashboard, and single-page site talks to an API behind the scenes, and that API makes security decisions based on data it receives from your browser. When those decisions are sloppy, you do not need to break in. You just ask politely for things you were never meant to see.</p><p>This path walks you through ten classic API flaws. You will pull full database rows out of a user list, rewrite your own account into an administrator, brute force a login that has no rate limit, forge JWTs three different ways, hijack an OAuth flow, regenerate someone else\'s API key, and slip through a forgotten API version and a loose CORS policy.</p><p>Each step builds on the last. Bring the habits you learned in Zero to Web Pentester: read raw responses, keep notes, and never assume the frontend tells the whole story. Finish all ten and you will think about every API you ever use a little differently.</p>',
  steps: [
    {
      moduleId: 'api',
      vulnId: 'exposure',
      note: 'The user list leaks full database rows. Fetch the raw JSON yourself, since the viewer hides the interesting parts, and see what comes back per user.',
    },
    {
      moduleId: 'api',
      vulnId: 'mass-assignment',
      note: 'PATCH merges every field you send. Look at what your account contains, then think about which single extra field would make you an admin.',
    },
    {
      moduleId: 'api',
      vulnId: 'rate-limit',
      note: 'No rate limit on login. Guess the password. Start with what you know about the account, then work through a sensible wordlist and watch the response times and messages.',
    },
    {
      moduleId: 'jwt',
      vulnId: 'none-admin',
      note: 'Forge an admin token with alg none. The server trusts what the token header says about its own algorithm, so ask yourself what a token with no signature would need to look like.',
    },
    {
      moduleId: 'jwt',
      vulnId: 'weak-secret',
      note: 'The signing secret is guessable. Guess it. Think about what a developer would pick as a placeholder secret, and try the obvious candidates first.',
    },
    {
      moduleId: 'oauth',
      vulnId: 'no-state',
      note: 'No state parameter. Hijack the flow. Watch how the callback works when two different logins interleave, and figure out which request the server is actually binding the login to.',
    },
    {
      moduleId: 'idor',
      vulnId: 'idor-apikey-regen',
      note: 'Regenerate someone else\'s API key. The endpoint takes an identifier it probably should not take from the request, so find it and point it at another user.',
    },
    {
      moduleId: 'api',
      vulnId: 'api-version-bypass',
      note: 'v2 forgot its authorization check. Compare how v1 and v2 of the same endpoint handle a record that is not yours, and use the version that asks fewer questions.',
    },
    {
      moduleId: 'jwt',
      vulnId: 'alg-confusion',
      note: 'Confuse RS256 with HS256. The server has a public key lying around, and it will accept it as an HMAC secret if you hand it back in the right form.',
    },
    {
      moduleId: 'cors',
      vulnId: 'cors-reflect',
      note: 'A reflected origin policy leaks authenticated data. Find the origin value the server echoes back, then reason about what a page on another site could read from this API in a logged-in browser.',
    },
  ],
};
