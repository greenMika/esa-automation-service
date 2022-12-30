import { CVE, CVEGroup, TCVESerialized } from "./services/CVE"

export type TRelizahSerialized = {
    meta: {
        lastFetched: Date
    }
    DSA: {
        version: string
        packages: string[]
    }
    DLA: {
        version: string
        packages: string[]
    }
}

export enum EApplianceSystem {
    DLA = "DLA",
    DSA = "DSA",
    UNDEFINED = "UNDEFINED",
}

export type TJiraIssue = {
    ID: string
    summaryText: string
    issueLink: string
    library: string
    system: EApplianceSystem
}

export type TCVEParcelDetails = {
    CVSS3SeverityInt: number
    CVSS3SeverityString: string
    site: ESeverityIntelligenceSites
}

export enum ESeverityIntelligenceSites {
    NVD = "NVD",
    REDHAT = "REDHAT",
}

export type TPotentialVulnerability = TJiraIssue & {
    CVEs: CVEGroup
    highestCVE: CVE
    shortDescription: string
    containsPackage: boolean
    fixedVersion: string
    currentVersion: string
    shortDescriptionFormatted: string
    similarNames: string[]
}

export type TPotentialVulnerabilitySerialized = TJiraIssue &
    Omit<TPotentialVulnerability, "highestCVE" | "CVEs" | "system"> & {
        CVEs: TCVESerialized[]
        highestCVE: TCVESerialized
        system: string
    }

export enum ESeverityString {
    CRITICAL = "CRITICAL",
    HIGH = "HIGH",
    MEDIUM = "MEDIUM",
    LOW = "LOW",
    LOG = "LOG",
    UNDEFINED = "UNDEFINED",
}

export interface IScrapingService {
    scrapeCVE: (cve: string) => Promise<TCVEParcelDetails>
}
