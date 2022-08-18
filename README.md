# Dynga-Web
Page for Dynga.

# Project structure
This is a summary of the essential project structure with an explanation of each element.

```
functions/                    <-- Firebase Cloud Functions for SSR
        renderer/             <-- Auto-generated JavaScript for SSR functions
        index.js              <-- Functions for Cloud Function deployment
src/                          <-- Standard SvelteKit project structure
static/                       <-- Static files for the Dynga-Web app
tests/                        <-- Tests for the Dynga-Web app
database-rules.json           <-- Realtime Database (Firebase) security rules
firebase.json                 <-- Firebase configuration
package.json                  <-- Node.js project / npm configuration
playwright.config.ts          <-- Config for Playwright tool
svelte.config.js              <-- SvelteKit configuration
tsconfig.dev.json             <-- Development-specific TypeScript configuration
tsconfig.json                 <-- Regular TypeScript configuration
vite.config.js                <-- Vite dev server configuration
```

# Design decisions
All design decisions that stray from the standard design are mentioned here.

## No TypeScript for Cloud Functions
Due to the beta status of SvelteKit and associated adapter I had to make a compromise in terms of TypeScript usage. Originally, this project was intended to be purely TypeScript, but due to the bugginess of the adapter's TypeScript integration (see [relevant issue here](https://github.com/jthegedus/svelte-adapter-firebase/issues/6)) it just turned out to be simpler to switch to regular JavaScript.
