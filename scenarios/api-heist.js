'use strict';

module.exports = {
  id: 'api-heist',
  name: 'API Heist',
  tagline: 'Leak it, forge it, walk away with everything.',
  difficulty: 'Intermediate',
  story: '<p>Acme Corp runs its whole mobile app on a private JSON API. The API is fast, the app is slick, and behind the polished UI the backend is held together with duct tape. Somewhere in that API are leaked database rows, a profile endpoint that trusts whatever you send it, an admin panel that will believe any token you forge, and a new API version whose authors forgot the one check that mattered.</p><p>You are the heist crew of one. The plan has four jobs. First, find the endpoint that leaks more than it should, and pull something useful out of the spill. Second, turn that useful thing into power: rewrite your own account into an administrator. Third, stop relying on their login flow at all, and mint your own admin token from scratch. Fourth, hit the forgotten endpoint they thought nobody would find, and take everything.</p><p>Every job builds on the last. Work quietly, keep notes, and by the end you will be holding Acme data and an admin session that are entirely yours.</p>',
  stages: [
    {
      id: 'leak',
      title: 'The Spill: full database rows in the open',
      moduleId: 'api',
      vulnId: 'exposure',
      briefing: '<p>Reconnaissance comes first. The API browser viewer lies by design, so fetch the raw JSON response yourself and read every field that comes back per user: one endpoint returns full database rows instead of tidy trimmed objects, and the response headers carry something interesting too. Your goal: find the leaking endpoint and take the useful thing out of the spill.</p>',
    },
    {
      id: 'escalate',
      title: 'The Promotion: rewrite your own account',
      moduleId: 'api',
      vulnId: 'mass-assignment',
      briefing: '<p>The profile update endpoint has a classic trust-the-client flaw: it merges every field you send into your account, with no list of which fields are actually allowed. Log in as your own lowly regular account and think about what single field an attacker would add to turn a nobody into a somebody. Your goal: change one field on your own account and walk out with administrator power.</p>',
    },
    {
      id: 'forge',
      title: 'The Forgery: mint your own admin token',
      moduleId: 'jwt',
      vulnId: 'none-admin',
      briefing: '<p>Being an admin is nice, but you are still asking Acme\'s login flow for permission, so stop asking. The token verification trusts what a token says about itself, which means a token that declares it needs no signature at all still gets believed, no secret key required. Your goal: build an admin token by hand and have the API believe it, without ever touching their secret.</p>',
    },
    {
      id: 'take-all',
      title: 'The Vault: the version they forgot to lock',
      moduleId: 'api',
      vulnId: 'api-version-bypass',
      briefing: '<p>Old API versions never really die; they just get cloned into new ones. Acme shipped a v2 of its user endpoint where v1 carefully checks that you only read your own record, but v2 forgot the authorization check entirely. Your goal: as a logged-in user, probe both versions on another user\'s record and take everything behind the door that swings open.</p>',
    },
  ],
};
