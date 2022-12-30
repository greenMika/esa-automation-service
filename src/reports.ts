import * as fs from "fs"
import { table } from "table"
import nunjucks from "nunjucks"
import {
    TPotentialVulnerability,
    TPotentialVulnerabilitySerialized,
} from "./types"

export const printAffected = () => {
    if (!fs.existsSync("results.json"))
        return console.error("Please scrape the data first")
    const results: TPotentialVulnerabilitySerialized[] = JSON.parse(
        fs.readFileSync("results.json").toString()
    )
    const affected = results.filter((res) => res.containsPackage)
    console.log(affected[0])
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
        res.CVEs.map((cve) => cve.cveIdentifier).join(",\n"),
        res.similarNames.join(",\n"),
        `${res.highestCVE.highestSeverity} - ${res.highestCVE?.highestSeverityTerm}`,
    ])
    console.log(table([headers, ...rows]))
}

export const printUnaffected = () => {
    if (!fs.existsSync("results.json"))
        return console.error("Please scrape the data first")
    const results = JSON.parse(fs.readFileSync("results.json").toString())
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
    if (!fs.existsSync("results.json"))
        return console.error("Please scrape the data first")
    const results = JSON.parse(fs.readFileSync("results.json").toString())
    const renderedHTML = nunjucks.render("template.njk", { results })
    fs.writeFileSync("dist/rendered.html", renderedHTML)
}
