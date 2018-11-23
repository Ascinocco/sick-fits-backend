const Mutations = {
  createItem(parent, args, ctx, info) {
    // TODO: check if they are logged in
    const item = ctx.db.mutation.createItem({ data: { ...args } });
  }
};

module.exports = Mutations;
