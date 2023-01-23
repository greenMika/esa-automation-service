import { Browser } from "puppeteer"
import {
    ESeverityIntelligenceSites,
    ESeverityString,
    IScrapingService,
    TCVEParcelDetails,
} from "../types"

export class RedhatScrapingService implements IScrapingService {
    browser

    constructor(browser: Browser) {
        this.browser = browser
    }

    scrapeCVE = async (cve: string) => {
        const page = await this.browser.newPage()
        try {
            console.log(` - scraping redhat ${cve}`)

            await page.goto("https://access.redhat.com/security/cve/" + cve)
            await page.waitForSelector("h1.headline", {
                timeout: 5000,
            })

            const result = await page.$$eval(".stat-number", (elem) => {
                const CVSS3SeverityInt = elem[1].textContent || "0"
                const CVSS3SeverityString = elem[0].textContent || "UNDEFINED"
                return {
                    CVSS3SeverityInt: parseFloat(CVSS3SeverityInt),
                    CVSS3SeverityString,
                    site: "REDHAT",
                }
            })
            console.log("SCRAPED redhat FOR", cve, "WITH", result)
            return {
                CVSS3SeverityInt: result.CVSS3SeverityInt,
                site: result.site,
                CVSS3SeverityString: result.CVSS3SeverityString,
            } as TCVEParcelDetails
        } catch (err) {
            console.log("Could not scrape redhat", err)
            return {
                CVSS3SeverityInt: 0,
                CVSS3SeverityString: ESeverityString.UNDEFINED,
                site: ESeverityIntelligenceSites.REDHAT,
            }
        } finally {
            page.close()
        }
    }
}
