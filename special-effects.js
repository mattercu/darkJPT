// Special effects sequence after clicking "Yes"
class SpecialEffects {
    constructor() {
        this.specialScreen1 = document.getElementById('specialScreen1');
        this.specialScreen2 = document.getElementById('specialScreen2');
        this.bgAudio = document.getElementById('bgAudio');
        this.audio1 = new Audio('https://files.catbox.moe/39azma.mp3');
        this.audio2 = new Audio('lủnnr');
        
        this.init();
    }

    init() {
        // Configure audio
        this.audio1.volume = 0.8;
        this.audio2.volume = 0.8;
        this.audio1.preload = 'auto';
        this.audio2.preload = 'auto';
    }

    async startSpecialSequence() {
        // Stop background music
        this.bgAudio.pause();
        this.bgAudio.currentTime = 0;

        // Step 1: Fade to black and show romantic text
        await this.showRomanticText();
        
        // Step 2: Show GIF and play second audio
        await this.showGifAndPlayAudio();
        
        // Step 3: Return to original flow
        await this.returnToMainFlow();
    }

    showRomanticText() {
        return new Promise((resolve) => {
            // Create and show first special screen
            if (!this.specialScreen1) {
                this.createSpecialScreens();
            }

            // Fade out main content
            document.querySelector('.wrap').style.opacity = '0';
            document.querySelector('.wrap').style.transition = 'opacity 1.2s ease';
            
            setTimeout(() => {
                this.specialScreen1.style.display = 'flex';
                this.specialScreen1.classList.add('fade-in');
                
                // Play first audio
                this.audio1.play().catch(e => console.log('Audio1 play error:', e));
                
                // Wait 4 seconds then resolve
                setTimeout(resolve, 4000);
            }, 1200);
        });
    }

    showGifAndPlayAudio() {
        return new Promise((resolve) => {
            // Hide first screen, show second screen with GIF
            this.specialScreen1.style.display = 'none';
            this.specialScreen2.style.display = 'flex';
            this.specialScreen2.classList.add('fade-in');
            
            // Play second audio
            this.audio2.play().catch(e => console.log('Audio2 play error:', e));
            
            // Wait 8 seconds then resolve
            setTimeout(resolve, 13000);
        });
    }

    returnToMainFlow() {
        return new Promise((resolve) => {
            // Fade out special screen
            this.specialScreen2.style.opacity = '0';
            this.specialScreen2.style.transition = 'opacity 1s ease';
            
            setTimeout(() => {
                // Remove special screens
                this.specialScreen1.style.display = 'none';
                this.specialScreen2.style.display = 'none';
                this.specialScreen2.style.opacity = '1';
                
                // Restore main content and start original loading
                document.querySelector('.wrap').style.opacity = '1';
                
                // Restart background music
                this.bgAudio.play().catch(e => console.log('Bg audio play error:', e));
                
                // Start the original loading sequence
                if (window.startLoadingSequence) {
                    window.startLoadingSequence();
                }
                
                resolve();
            }, 1000);
        });
    }

    createSpecialScreens() {
        // Create first special screen for romantic text
        const screen1 = document.createElement('div');
        screen1.id = 'specialScreen1';
        screen1.className = 'special-screen';
        screen1.innerHTML = `
            <div class="special-inner pulse">
                <div class="romantic-text">
                    trái đất thì có mặt trời 🌞<br>
                    còn anh thì có 1 đời bên em 💖
                </div>
                <div style="font-size: 48px; margin-top: 20px;">✨</div>
            </div>
        `;

        // Create second special screen for GIF
        const screen2 = document.createElement('div');
        screen2.id = 'specialScreen2';
        screen2.className = 'special-screen';
        screen2.innerHTML = `
            <div class="special-inner">
                <div class="gif-container">
                    <img src="https://media.giphy.com/media/lxxOGaDRk4f7R5TkBd/giphy.gif" alt="Celebration GIF">
                </div>
                <div style="margin-top: 20px; color: #ff4d8a; font-weight: 700; font-size: 18px;">
                    Đang tận hưởng khoảnh khắc này... 🎉
                </div>
            </div>
        `;

        document.body.appendChild(screen1);
        document.body.appendChild(screen2);

        this.specialScreen1 = screen1;
        this.specialScreen2 = screen2;
    }
}

// Initialize special effects
let specialEffects;

// Modify the existing yes button click handler
document.getElementById('btnYes').addEventListener('click', async function() {
    // Ensure original audio plays first (as in original code)
    try { 
        await document.getElementById('bgAudio').play(); 
    } catch(e) { 
        console.log('play blocked', e) 
    }
    
    // Initialize and start special sequence
    if (!specialEffects) {
        specialEffects = new SpecialEffects();
    }
    
    specialEffects.startSpecialSequence();
});
