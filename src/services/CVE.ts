import { Browser } from "puppeteer"
import {
    ESeverityIntelligenceSites,
    ESeverityString,
    IScrapingService,
    TCVEParcelDetails,
} from "../types"
import { NVDScrapingService } from "./NVDScrapingService"
import { RedhatScrapingService } from "./RedhatScrapingService"

export type TCVESerialized = {
    cveIdentifier: string
    highestSeverity: number
    highestParcel: TCVEParcelDetails
    metaParcels: TCVEParcelDetails[]
    scraped: boolean
    highestSeverityTerm: ESeverityString
}

export class CVE {
    cveIdentifier
    highestSeverity = 0
    highestSeverityTerm = ESeverityString.UNDEFINED
    highestParcel: TCVEParcelDetails = createEmptyCVEParcel()
    metaParcels: TCVEParcelDetails[] = []
    scraped = false

    constructor(cveIdentifier: string) {
        this.cveIdentifier = cveIdentifier
    }

    scrapeFromAllAvailableSites = async (browser: Browser) => {
        const scrapingServices: IScrapingService[] = [
            new NVDScrapingService(browser),
            new RedhatScrapingService(browser),
        ]

        for (const scraperIndex in scrapingServices) {
            const scraper = scrapingServices[scraperIndex]
            const scrapeResult: TCVEParcelDetails = await scraper.scrapeCVE(
                this.cveIdentifier
            )
            if (scrapeResult.CVSS3SeverityInt > this.highestSeverity) {
                this.highestSeverity = scrapeResult.CVSS3SeverityInt
                this.highestSeverityTerm = mapNumbers(this.highestSeverity)
                this.highestParcel = scrapeResult
            }
            this.scraped = true
            this.metaParcels.push(scrapeResult)
        }
    }

    serialize: () => TCVESerialized = () => {
        return {
            cveIdentifier: this.cveIdentifier,
            highestParcel: this.highestParcel,
            highestSeverity: this.highestSeverity,
            metaParcels: this.metaParcels,
            scraped: this.scraped,
            highestSeverityTerm: this.highestSeverityTerm,
        }
    }
}

export class CVEGroup {
    cves: CVE[]

    constructor(cves: CVE[]) {
        this.cves = cves
    }

    getHighestSeverity: () => number = () => {
        return Math.max(...this.cves.map((cve) => cve.highestSeverity))
    }

    getHighestCve = () => {
        return this.cves.reduce((acc, curr) => {
            if (curr.highestSeverity > acc.highestSeverity) return curr
            return acc
        }, new CVE(""))
    }

    scrapeAll = async (browser: Browser) => {
        for (const cve of this.cves) {
            await cve.scrapeFromAllAvailableSites(browser)
        }
    }
}

const createEmptyCVEParcel: () => TCVEParcelDetails = () => {
    return {
        CVSS3SeverityInt: 0,
        CVSS3SeverityString: ESeverityString.UNDEFINED,
        site: ESeverityIntelligenceSites.NVD,
    }
}

const mapNumbers = (int: number) => {
    if (int >= 9) {
        //Critical
        return ESeverityString.CRITICAL
    }

    if (int >= 7) {
        //High
        return ESeverityString.HIGH
    }

    if (int >= 4) {
        //Medium
        return ESeverityString.MEDIUM
    }

    if (int > 0) {
        //Low
        return ESeverityString.LOW
    }

    return ESeverityString.LOG
}
