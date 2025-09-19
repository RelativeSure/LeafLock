export default {
  async fetch(request, env, ctx) {
    try {
      return await env.ASSETS.fetch(request);
    } catch (error) {
      return new Response("Not Found", { status: 404 });
    }
  },
};
