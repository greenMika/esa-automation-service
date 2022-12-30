import { Browser } from "puppeteer"
import {
    ESeverityIntelligenceSites,
    ESeverityString,
    IScrapingService,
    TCVEParcelDetails,
} from "../types"

export class NVDScrapingService implements IScrapingService {
    browser

    constructor(browser: Browser) {
        this.browser = browser
    }

    scrapeCVE = async (cve: string) => {
        const page = await this.browser.newPage()
        try {
            console.log(` - scraping nvd ${cve}`)
            await page.goto("https://nvd.nist.gov/vuln/detail/" + cve)
            await page.waitForSelector(".severityDetail", {
                timeout: 5000,
            })
            const result =
                (await page.$eval("#Cvss3NistCalculatorAnchor", (elem) => {
                    const [CVSS3SeverityInt, CVSS3SeverityString] =
                        elem?.textContent?.split(" ") || ["0", "UNDEFINED"]
                    return {
                        CVSS3SeverityInt: parseInt(CVSS3SeverityInt),
                        CVSS3SeverityString,
                        site: "NVD",
                    }
                })) ||
                page.$eval("#Cvss3CnaCalculatorAnchor", (elem) => {
                    const [CVSS3SeverityInt, CVSS3SeverityString] =
                        elem?.textContent?.split(" ") || ["0", "UNDEFINED"]
                    return {
                        CVSS3SeverityInt: parseInt(CVSS3SeverityInt),
                        CVSS3SeverityString,
                        site: "NVD",
                    }
                })
            console.log("SCRAPED NVD FOR", cve, "WITH", result)
            return {
                CVSS3SeverityInt: result.CVSS3SeverityInt,
                site: result.site,
                CVSS3SeverityString: result.CVSS3SeverityString,
            } as TCVEParcelDetails
        } catch (err) {
            console.log("Could not scrape nvd", err)
            return {
                CVSS3SeverityInt: 0,
                CVSS3SeverityString: ESeverityString.UNDEFINED,
                site: ESeverityIntelligenceSites.NVD,
            }
        } finally {
            page.close()
        }
    }
}
