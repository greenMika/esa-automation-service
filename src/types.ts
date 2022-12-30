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

export type TCVEDetails = {
    cve: string
    nvd: TCVEParcelDetails
    redhat: TCVEParcelDetails
}

export type TCVEParcelDetails = {
    CVSS3SeverityInt: number
    CVSS3SeverityString: string
}

export type THighestCVEParcel = {
    nvd: TCVEParcelDetails
    redhat: TCVEParcelDetails
}

export type TPotentialVulnerability = TJiraIssue & {
    shortDescription: string
    CVEs: string[]
    detailedCVEs: TCVEDetails[]
    containsPackage: boolean
    fixedVersion: string
    currentVersion: string
    shortDescriptionFormatted: string
    similarNames: string[]
    highestCVE: TCVEParcelDetails
}

export enum ESeverityString {
    CRITICAL = "CRITICAL",
    HIGH = "HIGH",
    MEDIUM = "MEDIUM",
    LOW = "LOW",
    LOG = "LOG",
    UNDEFINED = "UNDEFINED",
}
