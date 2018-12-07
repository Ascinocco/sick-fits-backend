const bcrypt = require('bcryptjs');
const { randomBytes } = require('crypto');
const { promisify } = require('util');

const generateToken = require('../lib/generateToken');
const TOKEN_COOKIE_PARAMS = {
  httpOnly: true,
  maxAge: 1000 * 60 * 60 * 24 * 365
};

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
    ctx.response.cookie('token', token, TOKEN_COOKIE_PARAMS);

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
    ctx.response.cookie('token', token, TOKEN_COOKIE_PARAMS);

    // return user
    return user;
  },

  signout(parent, args, ctx, info) {
    ctx.response.clearCookie('token');
    return { message: 'Goodbye!' };
  },

  async requestReset(parent, args, ctx, info) {
    // check if it's a real user
    const user = await ctx.db.query.user({ where: { email: args.email } });
    if (!user) {
      throw new Error(`No such user found for email ${args.email}`);
    }
    // set a reset token and expiry
    const resetToken = (await promisify(randomBytes)(20)).toString('hex');
    const resetTokenExpiry = Date.now() + 3600000; // 1 hour from now
    const res = await ctx.db.mutation.updateUser({
      where: { email: args.email },
      data: { resetToken, resetTokenExpiry },
    });
    console.log(res);
    return { message: 'Thanks!' };
    // email reset token
  },

  async resetPassword(parent, args, ctx, info) {
    // check if passwords match
    if (args.password !== args.confirmPassword) {
      throw new Error('Yo password don\'t match');
    }

    // check if reset token is valid
    const [user] = await ctx.db.query.users({
      where: {
        resetToken: args.resetToken,
        resetTokenExpiry_gte: Date.now() - 3600000,
      }
    });
    
    // check if reset token is expired
    if (!user) {
      throw new Error('This token is either invalid or expired');
    }

    // hash new password
    const password = await bcrypt.hash(args.password, 10);

    // save new password to user
    // remove old reset token field
    const updatedUser = await ctx.db.mutation.updateUser({
      where: { email: user.email },
      data: {
        password,
        resetToken: null,
        resetTokenExpiry: null,
      },
    });

    // generate jwt
    const token = generateToken(updatedUser.id);

    // set jwt cookie
    ctx.response.cookie('token', token, TOKEN_COOKIE_PARAMS);

    // return new user
    return updatedUser;
  }
};

module.exports = Mutations;
