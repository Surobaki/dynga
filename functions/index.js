const functions = require("firebase-functions");

let rendererServer;
exports.renderer = functions.region("us-central1").https.onRequest(
    async (request, response) => {
      if (!rendererServer) {
        functions.logger.info("Initialising SvelteKit SSR entry");
        rendererServer = require("./renderer/index").default;
        functions.logger.info("SvelteKit SSR entry initialised!");
      }
      functions.logger.info("Requested resource: " + request.originalUrl);
      return rendererServer(request, response);
    });

// // Create and Deploy Your First Cloud Functions
// // https://firebase.google.com/docs/functions/write-firebase-functions
//
// exports.helloWorld = functions.https.onRequest((request, response) => {
//   functions.logger.info("Hello logs!", {structuredData: true});
//   response.send("Hello from Firebase!");
// });
