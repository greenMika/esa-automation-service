import puppeteer, { Browser, Page } from "puppeteer"

import { config } from "dotenv"
import * as path from "path"

config({ path: path.resolve(__dirname, "../.env") })

import * as fs from "fs"
import {
    TJiraIssue,
    TPotentialVulnerability,
    TPotentialVulnerabilitySerialized,
    TRelizahSerialized,
} from "./types"
import { CVE, CVEGroup } from "./services/CVE"
import { cookiesPath, relizahPath, resultsPath } from "./constants"

const username = process.env.JIRA_USERNAME
const password = process.env.JIRA_PASSWORD

if (!username || !password)
    throw Error("Set JIRA_USERNAME and JIRA_PASSWORD in env")

const saveResult = (
    name: string,
    results: TPotentialVulnerabilitySerialized[]
) => {
    fs.writeFileSync(name, JSON.stringify(results))
    console.log("Saved to ", resultsPath)
}

const getReLizahData = async (renew = false) => {
    const dataPresent = fs.existsSync(relizahPath)
    let refetchData = renew
    if (dataPresent && !renew) {
        console.log("Found saved Relizah data, using it...")
        const relizahData = JSON.parse(
            fs.readFileSync(relizahPath).toString() || "{}"
        )
        const lastFetchedDate = new Date(
            relizahData?.meta?.lastFetched
        ).getTime()
        const oneDayAgo = Date.now() - 86400000
        refetchData = lastFetchedDate < oneDayAgo
        if (refetchData) {
            console.log("Saved relizah data is outdated, refetching ...")
        } else {
            console.log(
                `Using RelizahData from ${new Date(
                    lastFetchedDate
                ).toUTCString()} with DSA: ${
                    relizahData.DSA.version
                } and DLA: ${relizahData.DLA.version}`
            )
            return [relizahData.DLA.packages, relizahData.DSA.packages]
        }
    } else {
        console.log("Refetching Relizah data ...")
    }

    const browser = await puppeteer.launch({ headless: true })
    const page = await browser.newPage()

    // fetching newest relizah packages
    await page.goto("http://192.168.170.40/")
    await page.waitForSelector(".navbar-link")
    await page.waitForSelector("tr:first-child > td > button")
    await page.$$eval(".navbar-link", (links) => {
        links[links.length - 1].dispatchEvent(new Event("click"))
    })

    await page.waitForSelector("tr:first-child > td > button")

    await page.$$eval("tr:first-child > td > button", (buttons) => {
        buttons
            .find((button) => button.innerHTML.match(/Details/))
            ?.dispatchEvent(new Event("click"))
    })
    await page.waitForSelector(".packages-list")

    const DSAVersion = await page.$$eval(".snapshot-name", (packages) => {
        return packages[0]?.textContent?.trim() || "undefined"
    })

    console.log("USING DSA VERSION:", DSAVersion)

    const newestDSAPackages = (await page.$$eval(
        ".packages-list > li",
        (packages) => {
            return packages.map((i) => i.textContent?.trim()).filter((x) => x)
        }
    )) as string[]

    await page.reload()
    await page.waitForSelector(".navbar-link")
    await page.waitForSelector("tr:first-child > td > button")

    await page.$$eval(".navbar-link", (links) => {
        links[links.length - 2].dispatchEvent(new Event("click"))
    })

    await page.waitForSelector("tr:first-child > td > button")
    await page.$$eval("tr:first-child > td > button", (buttons) => {
        const detailButton = buttons
            .find((button) => button.innerHTML.match(/Details/))
            ?.dispatchEvent(new Event("click"))
        console.log(detailButton)
    })
    await page.waitForSelector(".packages-list")
    const DLAVersion = await page.$$eval(".snapshot-name", (packages) => {
        return packages[0]?.textContent?.trim() || "undefined"
    })

    console.log("USING DLA VERSION:", DLAVersion)
    const newestDLAPackages = (await page.$$eval(
        ".packages-list > li",
        (packages) => {
            return packages.map((i) => i.textContent?.trim()).filter((x) => x)
        }
    )) as string[]

    console.log(newestDLAPackages, newestDSAPackages)
    await browser.close()

    const relizahSerialized: TRelizahSerialized = {
        meta: {
            lastFetched: new Date(),
        },
        DSA: {
            version: DSAVersion,
            packages: newestDSAPackages,
        },
        DLA: {
            version: DLAVersion,
            packages: newestDLAPackages,
        },
    }

    fs.writeFileSync(relizahPath, JSON.stringify(relizahSerialized))
    return [newestDLAPackages, newestDSAPackages]
}

const login = async (browser: Browser) => {
    const page = await browser.newPage()
    await setCookies(page)
    await page.goto("https://jira.greenbone.net/login.jsp")
    await page.type("#login-form-username", username)
    await page.type("#login-form-password", password)
    await page.evaluate(() => {
        document
            .querySelector("#login-form-remember-me")
            ?.parentElement?.click()
    })
    await page.click("#login-form-submit")
    await page.waitForTimeout(1000)
    await saveCookiesToFile(page)
    return page
}

const getESAIssueList = async (browser: Browser) => {
    const page = await login(browser)
    await page.waitForSelector(".issuerow")
    // getting issues on just the first pagehttps://jira.greenbone.net/issues/?filterId=${layout.filterId}&startIndex=20
    const pages = await page.$$eval(".pagination > a", (pageButton) =>
        pageButton.map((d) => d.getAttribute("href"))
    )
    pages.pop()
    let allIssues: TJiraIssue[] = []
    for (const pageIndex in pages) {
        const link = pages[pageIndex]
        const issues: TJiraIssue[] = (await page.$$eval(".issuerow", (rows) => {
            return rows.map((row) => {
                const ID = row.querySelector(".issuekey > a")?.textContent
                const summaryText = row.querySelector(".summary a")?.textContent
                const issueLink = row
                    .querySelector(".summary a")
                    ?.getAttribute("href")
                const system = RegExp(/\[DLA.+\]/).test(summaryText || "")
                    ? "DLA"
                    : RegExp(/\[DSA.+\]/).test(summaryText || "")
                    ? "DSA"
                    : undefined
                const library =
                    summaryText?.match(
                        /\].+\]\s(.+)\s(security|database|regression)\supdate/
                    )?.[1] || undefined
                return {
                    ID: ID || "undefined",
                    summaryText: summaryText || "undefined",
                    issueLink: issueLink || "undefined",
                    system: system || "UNDEFINED",
                    library: library || "undefined",
                }
            })
        })) as TJiraIssue[]
        console.log(link, pageIndex, issues)
        if (parseInt(pageIndex) !== pages.length - 1) {
            await page.$$eval(
                ".pagination > a",
                (pageButton, index) =>
                    pageButton[index as unknown as number].dispatchEvent(
                        new Event("click")
                    ),
                pageIndex
            )
            await page.waitForTimeout(2000)
        }
        allIssues = [...allIssues, ...issues]
    }
    console.log("4")
    console.log(
        allIssues.length,
        allIssues.map((x) => x.library)
    )
    await page.close()
    return [...new Set(allIssues.map((x) => x.issueLink))].map((x) =>
        allIssues.find((a) => a.issueLink === x)
    )
}

const setCookies = async (page: Page) => {
    if (!fs.existsSync(cookiesPath)) {
        fs.writeFileSync(cookiesPath, "[]")
    }
    const foundCookies = JSON.parse(fs.readFileSync(cookiesPath).toString())
    if (foundCookies) {
        await page.setCookie(...foundCookies)
    }
}
const saveCookiesToFile = async (page: Page) => {
    const cookies = await page.cookies()
    fs.writeFileSync(cookiesPath, JSON.stringify(cookies))
}

const parseIssues = async (
    browser: Browser,
    issues: TJiraIssue[],
    newestDSAPackages: string[],
    newestDLAPackages: string[]
) => {
    const page = await login(browser)
    console.log("parsing", issues.length)
    const results: TPotentialVulnerability[] = []
    for (const issueIndex in issues) {
        const issue = issues[issueIndex]
        if (!issue.library || !issue.system) {
            console.error(`unrecognizable library: ${issue.summaryText}`)
            console.error(`continuing ...`)
            continue
        }
        console.log(
            "Checking library",
            issue.library,
            "for",
            issue.system,
            "...."
        )
        await page.goto(issue.issueLink)
        try {
            const description = await page.$eval(
                "#description-val > .user-content-block",
                //@ts-ignore
                (block) => block?.innerText
            )
            const shortDescription = description
                .replace(/\n/g, " ")
                .match(/(Package(.|\n)+)We\srecommend/)?.[1]
                ?.trim()
            const shortDescriptionFormatted = description
                .match(/(Package(.|\n)+)We\srecommend/)?.[1]
                ?.trim()
            //const shortDescription = description.match(/Package\s:\s(\w+).+\sVersion\s:\s(\w+)\s.+CVE\sID\s:\s(\w+)\s.+Debian Bug\s:\s(\w+)\s.+We recommend/)
            const fixedVersion =
                shortDescription.match(
                    /fixed\s+in\s+version (.+)\.\s+\w/
                )?.[1] ||
                shortDescription.match(/fixed\s+in\s+version (.+)\./)[1]

            const CVEIdentifier: string[] =
                shortDescription
                    .match(/CVE\s+ID\s:\s((CVE-\d{4}-\d+\s)+)./)?.[1]
                    .trim()
                    .split(" ") || []

            const relizahPackages =
                issue.system === "DSA" ? newestDSAPackages : newestDLAPackages
            const cveGroup = new CVEGroup(
                CVEIdentifier.map((cveIdentifier) => new CVE(cveIdentifier))
            )

            const similarNames = relizahPackages.filter(
                (pack: string) =>
                    pack !==
                        relizahPackages.find((pack: string) =>
                            pack.match(`^(lib)?${issue.library}`)
                        ) && pack.match(`${issue.library}`)
            )

            const result: TPotentialVulnerability = {
                shortDescription,
                containsPackage:
                    !!relizahPackages.find((pack: string) =>
                        pack.match(`^(lib)?${issue.library}`)
                    ) || similarNames.length > 0,
                CVEs: cveGroup,
                highestCVE: cveGroup.getHighestCve(),
                fixedVersion,
                currentVersion:
                    relizahPackages.find((pack: string) =>
                        pack.match(`^(lib)?${issue.library}`)
                    ) || "undefined",
                shortDescriptionFormatted,
                similarNames,
                ...issue,
            }

            results.push(result)
        } catch (e) {
            console.error(
                "Failed parsing, check for reference",
                issue.issueLink,
                issue.library,
                issue.summaryText
            )
            console.error(e)
        }
    }
    return results
}

export default async (complete: boolean) => {
    const [newestDLAPackages, newestDSAPackages] = await getReLizahData()

    const browser = await puppeteer.launch({ headless: false })
    let issues = (await getESAIssueList(browser)) as TJiraIssue[]

    if (!complete) {
        if (!fs.existsSync(resultsPath))
            return console.error("Please scrape the data first")
        const results: TPotentialVulnerability[] = JSON.parse(
            fs.readFileSync(resultsPath).toString()
        )
        issues = issues.filter((is) => !results.find((res) => res.ID === is.ID))
    }
    const results = await parseIssues(
        browser,
        issues,
        newestDSAPackages,
        newestDLAPackages
    )
    results
        .filter((res) => res.containsPackage)
        .forEach((pack) => {
            console.log(`[FOUND] -> ${pack.library} (${pack.issueLink})`)
        })

    const CVEs: CVEGroup[] = results
        .filter((res) => res.containsPackage)
        .map((res) => res.CVEs)

    for (const cveGroup of CVEs) {
        await cveGroup.scrapeAll(browser)
    }
    await browser.close()

    const serializedData: TPotentialVulnerabilitySerialized[] =
        results.map(serializeResult)

    saveResult(resultsPath, serializedData)
}

const serializeResult: (
    result: TPotentialVulnerability
) => TPotentialVulnerabilitySerialized = (result) => {
    const resultClone = { ...result }
    const CVEs = resultClone.CVEs
    delete (resultClone as Partial<TPotentialVulnerability>).CVEs
    const serialized: TPotentialVulnerabilitySerialized = {
        ...resultClone,
        system: resultClone.system,
        CVEs: CVEs.cves.map((cve) => cve.serialize()),
        highestCVE: CVEs.getHighestCve().serialize(),
    }
    return serialized
}
