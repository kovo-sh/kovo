# Guardian prototype

Local TypeScript prototype of the Guardian run workspace. Requires Node.js 22.18 or newer.

```sh
npm ci
npm run build
npm start
```

Open http://localhost:8000. Set `PORT` to use a different port.

The demo opens at the post-discovery scope gate. In **Overview**, select **Review scope** to approve hosts directly in the discovery inventory. You can inspect the discovery evidence and return to the form with your selections intact. Approve the hosts to open the execution trace with the first two Analysis workers running. Select **Show first result** to record a simulated evidence return.

The **Coordinator** conversation sits next to the workflow in a collapsible right pane. Select a worker to open its read-only thread in the same pane. Use the two tabs to switch between the run conversation and the selected worker. **Chat** in the toolbar toggles the pane.

Select **Trace** for all 34 threads, or press `/` to search. Use arrow keys to navigate search results and worker nodes, **Enter** to open a thread, and **Escape** to close it. **Copy link** creates a URL for the selected demo thread. Use **View** to change navigation, layout, palette, or appearance. **System** follows your device’s light/dark setting.

Stop the run to see a partial case file, or finish verification to see the complete report. Use **New demo run** to start with electronic discovery consent. In coordinator chat, send `Revise: <goal>` to record a goal revision.

The model connection, coordinator, and workers are simulated. Verification compares fictional evidence with a prepared control fixture in the scripted demo. Run state resets with the page. The prototype contains no Artex records.
