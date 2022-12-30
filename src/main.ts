import commandLineUsage from "command-line-usage"
import commandLineArgs from "command-line-args"
import scraper from "./scraper"

import { printUnaffected, printAffected, generateHTML } from "./reports"
;(async () => {
    const sections = [
        {
            header: "ESA Automation",
            content:
                "Scrapes and reports affected ESA libraries implemented in GOS",
        },
        {
            header: "Options",
            optionList: [
                {
                    name: "unaffected",
                    description: "Shows unaffected libraries of ESA Tickets.",
                },
                {
                    name: "affected",
                    description: "Shows affected libraries of ESA Tickets.",
                },
                {
                    name: "scrape-complete",
                    description:
                        "Scrape all ESA Tickets and regenerate reports",
                },
                {
                    name: "scrape",
                    description:
                        "Scrape new ESA Tickets and regenerate reports",
                },
                {
                    name: "help",
                    description: "Print this usage guide.",
                },
                {
                    name: "render-html",
                    description: "Render a html file containing the results.",
                },
            ],
        },
    ]
    const usage = commandLineUsage(sections)
    const optionDefinitions = [
        { name: "unaffected", alias: "u", type: Boolean },
        { name: "affected", alias: "a", type: Boolean },
        { name: "scrape", alias: "s", type: Boolean },
        { name: "scrape-complete", type: Boolean },
        { name: "render-html", type: Boolean },
        { name: "help", alias: "h", type: Boolean },
    ]
    const options = commandLineArgs(optionDefinitions)
    if (options.help) {
        return console.log(usage)
    }

    if (options.unaffected) {
        printUnaffected()
        return
    }

    if (options["scrape-complete"]) {
        await scraper(true)
        printAffected()
        return
    }

    if (options["scrape"]) {
        await scraper(false)
        printAffected()
        return
    }

    if (options.affected) {
        printAffected()
    }

    if (options["render-html"]) {
        generateHTML()
    }
})()
