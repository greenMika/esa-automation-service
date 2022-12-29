module.exports = {
    singleQuote: false,
    tabWidth: 4,
    semi: false,
    trailingComma: "es5",
    overrides: [
        {
            files: "*.json",
            options: {
                tabWidth: 2,
            },
        },
        {
            files: "*.yml",
            options: {
                tabWidth: 2,
            },
        },
    ],
}
