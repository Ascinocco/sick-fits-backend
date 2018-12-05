const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const Mutations = {
  async createItem(parent, args, ctx, info) {
    // TODO: check if they are logged in
    const item = await ctx.db.mutation.createItem({ data: { ...args } }, info);
    return item;
  },
  updateItem(parent, args, ctx, info) {
    // this syntax takes a copy instead of a reference I believe
    const updates = { ...args };
    delete updates.id;
    return ctx.db.mutation.updateItem({
      data: updates,
      where: {
        id: args.id,
      },
    }, info);
  },
  async deleteItem(parent, args, ctx, info) {
    const where = { id: args.id };
    const item = await ctx.db.query.item({ where }, `{ id title }`);
    return ctx.db.mutation.deleteItem({ where }, info);
  },

  async signup(parent, args, ctx, info) {
    // lower case email, because users do user things
    const email = args.email.toLowerCase();
    const password = await bcrypt.hash(args.password, 10);

    const userInfo = {
      ...args,
      email,
      password,
      permissions: { set: ['USER'] },
    };

    const user = await ctx.db.mutation.createUser({ data: userInfo }, info);
    const token = jwt.sign({ userId: user.id }, process.env.APP_SECRET);
    // HTTP Only makes it so that external javascript & browser extensions can't access your cookie, this is important for security
    // we set the max age of the cookie to 1 year so that we don't get logged out
    ctx.response.cookie('token', token, { httpOnly: true, maxAge: 1000 * 60 * 60 * 24 * 365 });

    // returning user here returns the user to the browser. It seems you don't have to
    // write an http response...?
    return user;
  }
};

module.exports = Mutations;
