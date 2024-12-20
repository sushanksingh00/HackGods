gsap.from(".comeup",{
    opacity:0,
    duration:2.2, 
    y:20,
    delay:1,
})
gsap.from(".intro",{
    opacity:0,
    duration:0.5,
    y:20,
    delay:0,
    stagger:1
})
gsap.from(".para",{
    opacity:0,
    duration:1,
    y:20,
    delay:3.2,
})
gsap.from(".navb",{
    opacity:0,
    duration:0.2,
    y:10,
    delay:1,
    scrollTrigger:{
        trigger:".new-section",
        scroller:"body",
        markers:true,
        scrub:5
    }
})
gsap.from("#details",{
    opacity:0,
    duration:1,
    y:20,
    delay:3,
    stagger:1
})