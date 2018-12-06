const bcrypt = require('bcryptjs');

const generateToken = require('../lib/generateToken');

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
    const token = generateToken(user.id);
    // HTTP Only makes it so that external javascript & browser extensions can't access your cookie, this is important for security
    // we set the max age of the cookie to 1 year so that we don't get logged out
    ctx.response.cookie('token', token, { httpOnly: true, maxAge: 1000 * 60 * 60 * 24 * 365 });

    // returning user here returns the user to the browser. It seems you don't have to
    // write an http response...?
    return user;
  },

  async signin(parent, { email, password }, ctx, info) {
    // check for user
    const user = await ctx.db.query.user({ where: { email } });
    if (!user) {
      // throwing the error allows our frontend querys/mutations to recieve the error object
      throw new Error(`No such user found for email ${email}`);
      // if an error is thrown it returns automatically
    }

    // validate password
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      throw new Error('Invalid password!');
    }

    // generate jwt
    const token = generateToken(user.id);

    // set cookie with token
    ctx.response.cookie('token', token, {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 365
    });

    // return user
    return user;
  },
};

module.exports = Mutations;
