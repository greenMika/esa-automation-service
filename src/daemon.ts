import cron from "node-cron"
import { config } from "dotenv"
import * as path from "path"
import scraper from "./scraper"
import { generateHTML } from "./reports"
import { startServer } from "./server"

config({ path: path.resolve(__dirname, "../.env") })

const cronSchedule = process.env.CRONJOB_SCHEDULE || "0 12,18 * * *"
const initCron = () => {
    console.log(`Started cron at ${new Date().toISOString()}`)
    console.log(`Cron Schedule:  ${cronSchedule}`)
    console.log("Starting express server ...")
    startServer()
    cron.schedule(cronSchedule, () => {
        scraper(true).then(() => generateHTML())
    })
}

initCron()
