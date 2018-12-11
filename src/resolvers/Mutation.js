const bcrypt = require('bcryptjs');
const { randomBytes } = require('crypto');
const { promisify } = require('util');
const { transport, makeANiceEmail } = require('../mail');
const { hasPermission } = require('../utils');
const stripe = require('../stripe');

const generateToken = require('../lib/generateToken');
const TOKEN_COOKIE_PARAMS = {
  httpOnly: true,
  maxAge: 1000 * 60 * 60 * 24 * 365
};

const Mutations = {
  async createItem(parent, args, ctx, info) {
    // TODO: check if they are logged in
    if (!ctx.request.userId) {
      throw new Error('You must be logged in to do that!');
    }

    const item = await ctx.db.mutation.createItem({
      data: {
        ...args,
        // this is how we create relationships between the item and the user
        user: {
          connect: {
            id: ctx.request.userId,
          },
        },
      },
    },info);
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
    const item = await ctx.db.query.item({ where }, `{ id title user { id } }`);
    const ownsItem = item.user.id === ctx.request.userId;
    const hasPermissions = ctx
                            .request
                            .user
                            .permissions
                            .some(
                              permission => ['ADMIN', 'ITEMDELETE']
                              .includes(permission)
                            )
    
    if (!ownsItem || !hasPermission) {
      throw new Error('You don\'t have permission to do that')
    }

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

    // this could be wrapped in a try catch to handle if the error failed
    const mailRes = await transport.sendMail({
      from: 'anthony@mail.io',
      to: user.email,
      subject: 'Your password reset token',
      html: makeANiceEmail(`
        Your password reset token has arrived!
        <a href="${process.env.FRONTEND_URL}/reset?resetToken=${resetToken}">
          Click here to reset.
        </a>
      `),
    });
    
    return { message: 'Thanks!' };
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
  },

  async updatePermissions(parent, args, ctx, info) {
    if (!ctx.request.userId) {
      throw new Error('You musted be logged in!');
    }

    const currentUser = await ctx.db.query.user({
      where: { id: ctx.request.userId },
    }, info)

    hasPermission(currentUser, ['ADMIN', 'PERMISSIONUPDATE']);

    return await ctx.db.mutation.updateUser({
      data: { permissions: { set: args.permissions } },
      where: { id: args.userId },
    }, info)
  },

  async addToCart(parent, args, ctx, info) {
    const { userId } = ctx.request;
    if (!userId) {
      throw new Error('You must be signed in');
    }

    const [existingCartItem] = await ctx.db.query.cartItems({
      where: {
        user: { id: userId },
        item: { id: args.id },
      },
    });

    if (existingCartItem) {
      return await ctx.db.mutation.updateCartItem({
        data: { quantity: existingCartItem.quantity + 1 },
        where: { id: existingCartItem.id }
      }, info);
    } 

    const result = await ctx.db.mutation.createCartItem({
      data: {
        user: { connect: { id: userId } },
        item: { connect: { id: args.id } }
      },
    }, info);
    console.log('RESULT', result);
    return result;
  },
  async removeFromCart(parent, args, ctx, info) {
    const cartItem = await ctx.db.query.cartItem({
      where: { id: args.id },
    },`{ id, user { id } }`);

    if (!cartItem) throw new Error('No Cart Item Found!');
    if (cartItem.user.id !== ctx.request.userId) throw new Error('You do not have the permission to delete this item');

    return await ctx.db.mutation.deleteCartItem({
      where: { id: args.id },
    }, info);
  },
  async createOrder(parent, args, ctx, info) {
    // validate user
    const { userId } = ctx.request;
    if (!userId) throw new Error('You must be signed in to complete this order');
    const user = await ctx.db.query.user(
      { where: { id: userId } },
      `{id name email cart { id quantity item { title price id description image largeImage }}}`,
    );
    // recalculate total price in case users try to edit price on client
    const amount = user.cart.reduce((tally, cartItem) => tally + cartItem.item.price * cartItem.quantity, 0);
    console.log('AMOUNT IS:  ===  ', amount);
    // create stripe charge (turn token into $$$)
    const charge = await stripe.charges.create({ // check the strip doc's for more options
      amount,
      currency: 'USD',
      source: args.token,
    });

    // convert cart items to order items
    const orderItems = user.cart.map((cartItem) => {
      const orderItem = {
        ...cartItem.item,
        quantity: cartItem.quantity,
        user: { connect: { id: userId }},
      };
      delete orderItem.id;
      return orderItem;
    })

    // create the order
    const order = await ctx.db.mutation.createOrder({
      data: {
        total: charge.amount,
        charge: charge.id,
        items: { create: orderItems },
        user: { connect: { id: userId } },
      }
    }); // you can catch the error here with a .catch
    // clean up - clear users cart, delete cart items
    const cartItemIds = user.cart.map(cartItem => cartItem.id);
    await ctx.db.mutation.deleteManyCartItems({ where: { id_in: cartItemIds } });

    // return the order to the client
    return order;
  }
};

module.exports = Mutations;
