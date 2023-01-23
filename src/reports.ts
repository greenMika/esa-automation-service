import * as fs from "fs"
import { table } from "table"
import nunjucks from "nunjucks"
import {
    TPotentialVulnerability,
    TPotentialVulnerabilitySerialized,
} from "./types"
import { resultsPath, staticPath } from "./constants"
import path from "path"

export const printAffected = () => {
    console.log("Printing affected packages ...")
    if (!fs.existsSync(resultsPath))
        return console.error("Please scrape the data first")
    const results: TPotentialVulnerabilitySerialized[] = JSON.parse(
        fs.readFileSync(resultsPath).toString()
    )
    const affected = results.filter((res) => res.containsPackage)
    const headers = [
        "ESA",
        "Library",
        "Current version",
        "Fixed Version",
        "CVEs",
        "Similar Names",
        "Highest CVSS",
    ]
    const rows = affected.map((res) => [
        `${res.issueLink}\n${res.system}`,
        res.library,
        res.currentVersion,
        res.fixedVersion,
        [
            ...res.CVEs.sort((a, b) => {
                return b.highestSeverity - a.highestSeverity
            }),
        ]
            .splice(0, 4)
            .map((cve) => `${cve.cveIdentifier} - ${cve.highestSeverity}`)
            .join(",\n"),
        res.similarNames.join(",\n"),
        `${res.highestCVE.highestSeverity} - ${res.highestCVE?.highestSeverityTerm}`,
    ])
    console.log(table([headers, ...rows]))
}

export const printUnaffected = () => {
    console.log("Printing unaffected packages ...")
    if (!fs.existsSync(resultsPath))
        return console.error("Please scrape the data first")
    const results = JSON.parse(fs.readFileSync(resultsPath).toString())
    const unaffected = results.filter(
        (res: TPotentialVulnerability) => !res.containsPackage
    )
    const headers = ["Summary", "Library", "Similar names", "Fixed version"]
    const rows = unaffected.map((res: TPotentialVulnerability) => [
        res.summaryText,
        res.library,
        res.similarNames.join(",\n"),
        res.fixedVersion,
    ])
    console.log(
        table([headers, ...rows], {
            columns: { 0: { width: 23 }, 2: { width: 100 }, 3: { width: 30 } },
        })
    )
}

export const generateHTML = () => {
    if (!fs.existsSync(resultsPath))
        return console.error("Please scrape the data first")
    const results: TPotentialVulnerabilitySerialized[] = JSON.parse(
        fs.readFileSync(resultsPath).toString()
    )
    const mappedResults = results.map((result) => ({
        ...result,
        CVEs: result.CVEs.sort((a, b) => b.highestSeverity - a.highestSeverity)
            .splice(0, 4)
            .map((cve) => `${cve.cveIdentifier} - ${cve.highestSeverity}`)
            .join(",\n"),
    }))
    const renderedHTML = nunjucks.render(
        path.resolve(__dirname, "./template.njk"),
        { results: mappedResults }
    )
    fs.writeFileSync(staticPath + "/rendered.html", renderedHTML)
}
