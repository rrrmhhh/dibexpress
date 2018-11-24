// const { forwardTo } = require("prisma-binding");

const Query = {
  me(parent, args, ctx, info) {
    if (!ctx.request.userId) {
      return null;
    }
    return ctx.db.query.user(
      {
        where: { id: ctx.request.userId }
      },
      info
    );
  },
  async users(parent, args, ctx, info) {
    const users = await ctx.db.query.users();
    return users;
  }
};

module.exports = Query;
