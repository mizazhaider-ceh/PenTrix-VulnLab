'use strict';
// Scenario: Shop Takeover. A four-stage kill chain against the PenTrix Corner
// Store: get in as admin, escalate a lowly member account, loot the business
// logic, and leave a mark every visitor will see. Stage references use the
// module and challenge ids defined in modules/<id>/challenges/*.js.
module.exports = {
  id: 'shop-takeover',
  name: 'Shop Takeover',
  tagline: 'Break into the corner store, abuse its business logic, leave your mark.',
  difficulty: 'Intermediate',
  story: '<p>PenTrix Corner Store sells hoodies and stickers online, and its owner will not stop talking. At every meetup, in every chat channel, the same line: nobody can touch my shop, the login is bulletproof, the prices are server side, the site is clean.</p>' +
    '<p>You have heard it one too many times. Tonight the store meets a real customer. You slip through the front door without a password, walk a nobody member account into the back office, buy the flagship hoodie for pocket change, and sign the guestbook in ink every future visitor will see.</p>' +
    '<p>Four stages, one shop, zero mercy. By morning the owner will finally be right about one thing: his store is memorable.</p>',
  stages: [
    {
      id: 'break-in',
      title: 'Pick the Front Lock',
      moduleId: 'sqli',
      vulnId: 'login-bypass',
      briefing: '<p>The member sign in form builds its database query by gluing your input straight into a SQL string, and the owner swears it is bulletproof. Make that input be something other than a username. Log in as the shop admin without ever knowing the password.</p>',
    },
    {
      id: 'privilege-escalation',
      title: 'The Hidden Door',
      moduleId: 'idor',
      vulnId: 'admin',
      briefing: '<p>Sign in as an ordinary member, an alice or a bob, and the admin panel link is nowhere in the navigation. A missing link is not access control, it is a hidden door: ask yourself what the server actually checks when the panel URL is requested directly, then walk through it.</p>',
    },
    {
      id: 'price-loot',
      title: 'Pocket Change',
      moduleId: 'bizlogic',
      vulnId: 'biz-price-tamper',
      briefing: '<p>The flagship PenTrix Hoodie sells for fifty dollars, and your wallet disagrees. View the page source and watch how the price travels to the server: hidden fields are hidden from view, not from you. Check out with a price the catalog never authorized, and let the receipt confess.</p>',
    },
    {
      id: 'leave-your-mark',
      title: 'Leave Your Mark',
      moduleId: 'xss',
      vulnId: 'stored',
      briefing: '<p>Every great heist ends with a signature. The shop guestbook displays each message exactly as posted, to every visitor. Sign it in something stronger than words: a short script that runs when the page loads and reports back to the lab, proving your mark executes inside visitors\' browsers.</p>',
    },
  ],
};
