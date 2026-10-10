pkg install nodejs -y
node person-tracker.js --full alice

node person-tracker.js --full alice
node person-tracker.js --full --url https://github.com/alice
node person-tracker.js --multi https://x.com/alice alice https://linktr.ee/alice

node person-tracker.js <username>              # full sweep + enrich + store
node person-tracker.js --url <profile-url>     # start from a social link
node person-tracker.js --links <profile-url>   # just harvest links from a page
node person-tracker.js --site github alice     # single platform detail
node person-tracker.js --email a@b.com         # email lookup (Gravatar)

node person-tracker.js --url https://github.com/alice 🎩

Made In L0v3 bY kArmasec happy hunting 


