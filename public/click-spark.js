class ClickSpark {
    constructor() {
        this.sparkColor = '#fff';
        this.sparkSize = 10;
        this.sparkRadius = 15;
        this.sparkCount = 8;
        this.duration = 400;
        this.leasing = 'ease-out';
        this.extraScale = 1.0;
        this.sparks = [];
        this.canvas = null;
        this.ctx = null;
        this.startTime = null;
        this.resizeTimeout = null;
    }

    init() {
        this.canvas = document.createElement('canvas');
        this.canvas.id = 'click-spark-canvas';
        this.canvas.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        pointer-events: none;
        user-select: none;
        z-index: 9999;
      `;
        document.body.appendChild(this.canvas);
        this.ctx = this.canvas.getContext('2d');

        this.resize();
        window.addEventListener('resize', () => this.resize());

        document.addEventListener('pointerdown', (e) => this.handleClick(e));

        requestAnimationFrame((t) => this.draw(t));
    }

    resize() {
        const dpr = window.devicePixelRatio || 1;
        this.canvas.width = window.innerWidth * dpr;
        this.canvas.height = window.innerHeight * dpr;
        this.ctx.scale(dpr, dpr);
    }

    easeFunc(t) {
        switch (this.leasing) {
            case 'linear': return t;
            case 'ease-in': return t * t;
            case 'ease-in-out': return t < 0.5 ? 2 * t * t : -1 + (4 - 2 * t) * t;
            default: return t * (2 - t);
        }
    }

    handleClick(e) {
        const x = e.clientX;
        const y = e.clientY;
        const now = performance.now();

        for (let i = 0; i < this.sparkCount; i++) {
            this.sparks.push({
                x,
                y,
                angle: (2 * Math.PI * i) / this.sparkCount,
                startTime: now
            });
        }
    }

    draw(timestamp) {
        if (!this.startTime) this.startTime = timestamp;

        this.ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);

        this.sparks = this.sparks.filter(spark => {
            const elapsed = timestamp - spark.startTime;
            if (elapsed >= this.duration) return false;

            const progress = elapsed / this.duration;
            const eased = this.easeFunc(progress);

            const distance = eased * this.sparkRadius * this.extraScale;
            const lineLength = this.sparkSize * (1 - eased);

            const x1 = spark.x + distance * Math.cos(spark.angle);
            const y1 = spark.y + distance * Math.sin(spark.angle);
            const x2 = spark.x + (distance + lineLength) * Math.cos(spark.angle);
            const y2 = spark.y + (distance + lineLength) * Math.sin(spark.angle);

            this.ctx.strokeStyle = this.sparkColor;
            this.ctx.lineWidth = 2;
            this.ctx.beginPath();
            this.ctx.moveTo(x1, y1);
            this.ctx.lineTo(x2, y2);
            this.ctx.stroke();

            return true;
        });

        requestAnimationFrame((t) => this.draw(t));
    }
}

// Auto-init on load
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        new ClickSpark().init();
    });
} else {
    new ClickSpark().init();
}

