// This file connects to the remote prisma db
// and allows us to query it
const { Prisma } = require('prisma-binding');

const db = new Prisma({
  typeDefs: 'src/generated/prisma.graphql',
  endpoint: process.env.PRISMA_ENDPOINT,
  secret: process.env.PRISMA_SECRET,
  debug: process.env.PRISMA_DEBUG,
});

module.exports = db;
