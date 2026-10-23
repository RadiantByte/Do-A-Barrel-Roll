add_rules("mode.debug", "mode.release")
set_project("DoABarrelRoll")
set_version("1.0.0")
set_allowedplats("android")
set_allowedarchs("arm64-v8a")
set_languages("c++20")
add_requires("nlohmann_json v3.12.0")

target("DoABarrelRoll")
    set_kind("shared")
    set_basename("DoABarrelRoll")
    set_prefixname("")
    set_targetdir("bin")
    set_runtimes("c++_shared")
    set_symbols("none")
    set_strip("all")
    add_files(
        "src/main.cpp",
        "src/common/*.cpp",
        "src/config/*.cpp",
        "src/core/*.cpp",
        "src/game/*.cpp",
        "src/runtime/*.cpp",
        "src/ui/*.cpp"
    )
    add_includedirs("include", "src")
    add_packages("nlohmann_json")
    add_cxxflags("-g0", "-fPIC", "-fno-rtti", "-Wno-invalid-offsetof", "-fvisibility=hidden", "-fvisibility-inlines-hidden")
    add_links("android", "dl", "m")
    add_shflags("-Wl,-z,max-page-size=16384", "-Wl,--version-script=" .. path.join(os.projectdir(), "exports.map"), {force = true})
    if is_mode("release") then
        set_optimize("fast")
    end
    after_build(function(target)
        import("lib.detect.find_tool")
        os.tryrm(path.join(target:targetdir(), "DoABarrelRoll.sym"))
        local python = find_tool("python3") or find_tool("python")
        local args = {}
        if not python then
            python = find_tool("py")
            if python then table.insert(args, "-3") end
        end
        assert(python, "Python 3 is required to package DoABarrelRoll.levipack")
        table.insert(args, path.join(os.projectdir(), "scripts", "package_levipack.py"))
        table.insert(args, "--library")
        table.insert(args, target:targetfile())
        table.insert(args, "--output")
        table.insert(args, path.join(target:targetdir(), "DoABarrelRoll.levipack"))
        os.vrunv(python.program, args)
    end)
target_end()
