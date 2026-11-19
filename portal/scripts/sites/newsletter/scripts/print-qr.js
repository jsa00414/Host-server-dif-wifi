#!/usr/bin/env node
const fs = require("fs");
const path = require("path");
const { generateURI } = require("otplib");

const configPath = path.join(process.cwd(), "data", "config.json");
if (!fs.existsSync(configPath)) {
  console.error("No data/config.json found. Complete /setup first.");
  process.exit(1);
}

const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
const adminUri = generateURI({
  issuer: config.schoolName,
  label: `${config.className} Admin`,
  secret: config.adminTotpSecret,
});
const viewerUri = generateURI({
  issuer: config.schoolName,
  label: `${config.className} Families`,
  secret: config.viewerTotpSecret,
});

console.log("Admin otpauth URI:\n", adminUri);
console.log("\nFamily otpauth URI:\n", viewerUri);
console.log("\nAdmin secret:", config.adminTotpSecret);
console.log("Family secret:", config.viewerTotpSecret);
